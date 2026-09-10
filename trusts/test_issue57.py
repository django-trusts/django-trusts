"""Isolated TrustsRegistry registration tests (issue #57).

Registration only. Does not exercise object authorization, authorized-content
filtering, permission enumeration, backends, conditions, or compatibility.
"""

import types

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.core import (
    Ref,
    RegisteredRelation,
    TrustsConfigurationError,
    TrustsRegistry,
)


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
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
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
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Document, DocumentGrant, OtherGrant


def _register(registry, grant, content_attr='document'):
    j = Ref(grant)
    return registry.register(
        content=getattr(j, content_attr),
        user=j.user,
        permission=j.permission,
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryTest(SimpleTestCase):
    def test_successful_direct_registration_infers_root_and_terminals(self):
        Document, DocumentGrant, _other = _mock_models()
        User = get_user_model()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)

        record = registry.register(
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
        self.assertEqual(registry.records_for_root(DocumentGrant), (record,))
        self.assertEqual(registry.records, (record,))

    def test_all_refs_share_the_same_root(self):
        _document, DocumentGrant, _other = _mock_models()
        record = _register(TrustsRegistry(), DocumentGrant)
        self.assertIs(record.root, DocumentGrant)
        self.assertEqual(record.content_path[0], 'document')
        self.assertEqual(record.user_path[0], 'user')
        self.assertEqual(record.permission_path[0], 'permission')

    def test_mixed_roots_rejected(self):
        _document, DocumentGrant, OtherGrant = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        k = Ref(OtherGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'same root'):
            registry.register(
                content=j.document,
                user=k.user,
                permission=j.permission,
            )
        self.assertEqual(registry.records, ())

    def test_missing_field_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'missing field'):
            registry.register(
                content=j.missing,
                user=j.user,
                permission=j.permission,
            )

    def test_scalar_intermediate_traversal_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'scalar'):
            registry.register(
                content=j.document.title,
                user=j.user,
                permission=j.permission,
            )

    def test_multi_valued_traversal_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'multi-valued',
        ):
            registry.register(
                content=j.tags,
                user=j.user,
                permission=j.permission,
            )

    def test_reverse_traversal_rejected(self):
        Document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(Document)
        with self.assertRaisesRegex(TrustsConfigurationError, r'reverse'):
            registry.register(
                content=j.grants,
                user=j.grants,
                permission=j.grants,
            )
        self.assertFalse(hasattr(DocumentGrant, 'trust'))

    def test_generic_foreign_key_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'generic foreign key',
        ):
            registry.register(
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
                settings.AUTH_USER_MODEL, related_name='collision_path_grants',
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

        registry = TrustsRegistry()
        record = registry.register(
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

        alt = TrustsRegistry()
        via_path_content = alt.register(
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
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'must be a root-relative Ref'):
            registry.register(
                content='document',
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'non-empty'):
            registry.register(
                content=j,
                user=j.user,
                permission=j.permission,
            )

    def test_non_none_condition_rejected(self):
        _document, DocumentGrant, _other = _mock_models()
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'not supported'):
            registry.register(
                content=j.document,
                user=j.user,
                permission=j.permission,
                condition=object(),
            )
        record = registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
            condition=None,
        )
        self.assertIsNone(record.condition)

    def test_duplicate_and_conflicting_registration_are_deterministic(self):
        _document, DocumentGrant, OtherGrant = _mock_models()
        registry = TrustsRegistry()
        first = _register(registry, DocumentGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            _register(registry, DocumentGrant)
        self.assertEqual(registry.records, (first,))
        self.assertEqual(registry.records_for_root(DocumentGrant), (first,))

        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            _register(registry, DocumentGrant, content_attr='alt_document')
        self.assertEqual(registry.records, (first,))
        self.assertEqual(first.content_path, ('document',))

        other = _register(registry, OtherGrant)
        self.assertEqual(registry.records, (first, other))

        twin = TrustsRegistry()
        again = _register(twin, DocumentGrant)
        self.assertEqual(first, again)
        self.assertIsNot(first, again)
        self.assertEqual(twin.records, (again,))
        self.assertEqual(registry.records, (first, other))

    def test_normalized_records_are_immutable(self):
        _document, DocumentGrant, _other = _mock_models()
        record = _register(TrustsRegistry(), DocumentGrant)
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
        registry = TrustsRegistry()
        _register(registry, DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            _register(registry, DocumentGrant)
        j = Ref(DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.missing,
                user=j.user,
                permission=j.permission,
            )

    def test_no_historical_model_is_required(self):
        Document, DocumentGrant, OtherGrant = _mock_models()
        for model in (Document, DocumentGrant, OtherGrant):
            names = {cls.__name__ for cls in model.__mro__}
            self.assertNotIn('Trust', names)
            self.assertNotIn('Content', names)
            self.assertNotIn('Junction', names)
        record = _register(TrustsRegistry(), DocumentGrant)
        self.assertEqual(DocumentGrant.__module__, __name__)
        self.assertIs(record.root, DocumentGrant)

    def test_instances_are_isolated(self):
        _document, DocumentGrant, _other = _mock_models()
        left = TrustsRegistry()
        right = TrustsRegistry()
        _register(left, DocumentGrant)
        self.assertEqual(len(left.records), 1)
        self.assertEqual(right.records, ())

    def test_package_surface_does_not_reexport_registry(self):
        import trusts
        self.assertIsNone(getattr(trusts, 'TrustsRegistry', None))
        self.assertIsNone(getattr(trusts, 'RegisteredRelation', None))

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
