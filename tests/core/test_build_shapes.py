"""``build_*`` and ``build()`` return testable shapes.

``RegistryFactory.build_relation``, ``build_delegation``, and
``build_public_registration`` are the pure shape-building halves of
``register``, ``register_delegation``, and ``_register_public``. The
register methods own duplicate/rule checks and append the shapes.
``build()`` freezes those stored rows into one ``CatalogShape``.
"""

import dataclasses

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import Q
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from trusts.compile.catalogs import Catalog, CatalogShape
from trusts.compile.factory import (
    PublicRegistration,
    RegisteredDelegation,
    RegisteredRelation,
    RegistryFactory,
)
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.plan.conditions import ConditionRegistry, FrozenConditionLookup
from tests.support import built_catalog, forget_models


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class BuildRelationTest(SimpleTestCase):
    def test_build_relation_returns_frozen_shape_without_storing(self):
        Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        root = Ref(DocumentGrant)

        built = registry.build_relation(
            content=root.document, user=root.user,
            permission=root.permission,
        )

        self.assertIsInstance(built, RegisteredRelation)
        self.assertTrue(dataclasses.is_dataclass(built))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            built.root = DocumentGrant
        self.assertIs(built.root, DocumentGrant)
        self.assertEqual(built.content_path, ('document',))
        self.assertIs(built.content_model, Document)
        self.assertEqual(built.content_field, 'document')
        self.assertEqual(built.user_field, 'user')
        self.assertIs(built.user_model, get_user_model())
        self.assertEqual(built.permission_field, 'permission')
        self.assertIs(built.permission_model, Permission)
        self.assertFalse(built.via_group)
        self.assertIsNone(built.condition)
        self.assertIsNone(built.along)
        self.assertEqual(registry.records, ())

    def test_build_relation_equality_and_register_appends_same_shape(self):
        _Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        root = Ref(DocumentGrant)
        kwargs = dict(
            content=root.document, user=root.user,
            permission=root.permission,
        )

        built = registry.build_relation(**kwargs)
        self.assertEqual(built, registry.build_relation(**kwargs))

        stored = registry.register(**kwargs)
        self.assertEqual(stored, built)
        self.assertEqual(registry.records, (stored,))

    def test_build_relation_group_shape(self):
        Document, GroupGrant = _group_models()
        registry = RegistryFactory()
        root = Ref(GroupGrant)

        built = registry.build_relation(
            content=root.document, user=root.user, group=root.group,
        )

        self.assertTrue(built.via_group)
        self.assertEqual(built.group_path, ('group',))
        self.assertIs(built.group_model, Group)
        self.assertEqual(built.group_field, 'group')
        self.assertEqual(built.permission_path, ('group', 'permissions'))
        self.assertEqual(built.permission_field, 'group__permissions')
        self.assertIs(built.permission_model, Permission)
        self.assertIs(built.content_model, Document)
        self.assertEqual(registry.records, ())

    def test_build_relation_rejects_bad_permission_source_and_roots(self):
        _Document, DocumentGrant = _document_models()
        _Other, OtherGrant = _other_grant_models()
        registry = RegistryFactory()
        root = Ref(DocumentGrant)

        with self.assertRaises(TrustsConfigurationError):
            registry.build_relation(
                content=root.document, user=root.user,
                permission=root.permission, group=root.permission,
            )
        with self.assertRaises(TrustsConfigurationError):
            registry.build_relation(content=root.document, user=root.user)
        with self.assertRaises(TrustsConfigurationError):
            registry.build_relation(
                content=root.document, user=Ref(OtherGrant).user,
                permission=root.permission,
            )
        self.assertEqual(registry.records, ())

    def test_build_relation_after_build_still_builds_and_registers(self):
        _Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        root = Ref(DocumentGrant)
        built = registry.build_relation(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        self.assertIsInstance(built, RegisteredRelation)
        self.assertEqual(registry.records, ())
        record = registry.register(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        self.assertEqual(record, built)
        self.assertEqual(registry.records, (record,))
        self.assertEqual(built_catalog(registry).records, (record,))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class BuildDelegationTest(SimpleTestCase):
    def test_build_delegation_returns_shape_without_storing(self):
        Document, Share = _share_models()
        registry = RegistryFactory()
        root = Ref(Share)

        built = registry.build_delegation(
            content=root.document, delegate=root.delegate,
            sponsor=root.sponsor,
        )

        self.assertIsInstance(built, RegisteredDelegation)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            built.root = Share
        self.assertIs(built.root, Share)
        self.assertIs(built.content_model, Document)
        self.assertEqual(built.delegate_field, 'delegate')
        self.assertEqual(built.sponsor_field, 'sponsor')
        self.assertIs(built.delegate_model, get_user_model())
        self.assertIs(built.sponsor_model, built.delegate_model)
        self.assertIsNone(built.sponsor_rules)
        self.assertEqual(registry.delegations, ())

    def test_register_delegation_appends_shape_with_sponsor_rules(self):
        _Document, Share = _share_models()
        registry = RegistryFactory()
        root = Ref(Share)
        kwargs = dict(
            content=root.document, delegate=root.delegate,
            sponsor=root.sponsor,
        )

        built = registry.build_delegation(**kwargs)
        stored = registry.register_delegation(**kwargs)

        # sponsor_rules is compare=False: stored still equals the shape.
        self.assertEqual(stored, built)
        self.assertIsNotNone(stored.sponsor_rules)
        self.assertEqual(registry.delegations, (stored,))

    def test_build_delegation_rejects_mismatched_principals(self):
        _Document, Share = _share_models()
        registry = RegistryFactory()
        root = Ref(Share)

        with self.assertRaises(TrustsConfigurationError):
            registry.build_delegation(
                content=root.document, delegate=root.delegate,
                sponsor=root.document,
            )
        self.assertEqual(registry.delegations, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class BuildPublicRegistrationTest(SimpleTestCase):
    def test_build_public_registration_ordinary_shape(self):
        _Document, DocumentGrant = _document_models()
        registry = RegistryFactory()

        shape = registry.build_public_registration(
            trust=DocumentGrant, content='document', user='user',
            permission='permission',
        )

        self.assertIsInstance(shape, PublicRegistration)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            shape.trust = DocumentGrant
        self.assertEqual(shape, PublicRegistration(
            trust=DocumentGrant,
            content=Ref(DocumentGrant, ('document',)),
            user=Ref(DocumentGrant, ('user',)),
            permission=Ref(DocumentGrant, ('permission',)),
        ))
        self.assertIsNone(shape.group)
        self.assertIsNone(shape.delegate)
        self.assertEqual(registry.records, ())

        stored = registry._register_public(
            trust=DocumentGrant, content='document', user='user',
            permission='permission',
        )
        root = Ref(DocumentGrant)
        self.assertEqual(stored, registry.build_relation(
            content=root.document, user=root.user,
            permission=root.permission,
        ))
        self.assertEqual(registry.records, (stored,))

    def test_build_public_registration_invokes_builder_once(self):
        _Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        calls = []

        def content_builder(trust):
            calls.append(trust)
            return trust.document

        shape = registry.build_public_registration(
            trust=DocumentGrant, content=content_builder, user='user',
            permission='permission',
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            shape.content, Ref(DocumentGrant, ('document',)),
        )
        self.assertEqual(registry.records, ())

    def test_build_public_registration_group_and_delegated_shapes(self):
        _Document, GroupGrant = _group_models()
        _Doc2, Share = _share_models()
        registry = RegistryFactory()

        group_shape = registry.build_public_registration(
            trust=GroupGrant, content='document', user='user', group='group',
        )
        self.assertEqual(group_shape.group, Ref(GroupGrant, ('group',)))
        self.assertIsNone(group_shape.permission)

        delegated_shape = registry.build_public_registration(
            trust=Share, content='document', delegate='delegate',
            sponsor='sponsor',
        )
        self.assertEqual(
            delegated_shape.delegate, Ref(Share, ('delegate',)),
        )
        self.assertEqual(delegated_shape.sponsor, Ref(Share, ('sponsor',)))
        self.assertIsNone(delegated_shape.user)
        self.assertEqual(registry.records, ())
        self.assertEqual(registry.delegations, ())

    def test_build_public_registration_rejects_mixed_modes(self):
        _Document, DocumentGrant = _document_models()
        registry = RegistryFactory()

        with self.assertRaises(TrustsConfigurationError):
            registry.build_public_registration(
                trust=DocumentGrant, content='document', user='user',
                permission='permission', delegate='user', sponsor='user',
            )
        with self.assertRaises(TrustsConfigurationError):
            registry.build_public_registration(
                trust=DocumentGrant, content='document',
                delegate='user',
            )
        with self.assertRaises(TrustsConfigurationError):
            registry.build_public_registration(
                trust='not-a-model', content='document', user='user',
                permission='permission',
            )
        self.assertEqual(registry.records, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class BuildCatalogShapeTest(SimpleTestCase):
    def test_build_freezes_rows_and_fragments(self):
        Document, DocumentGrant = _document_models()
        registry = RegistryFactory()
        root = Ref(DocumentGrant)
        record = registry.register(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        condition = registry.register_permission_condition(
            Document, 'owned', lambda u, p, o: o.title == 'keep',
        )

        shape = registry.build()

        self.assertIsInstance(shape, CatalogShape)
        self.assertIs(shape.cls, RegistryFactory)
        self.assertEqual(shape.path, '')
        self.assertEqual(shape.family, 'relationship')
        self.assertTrue(dataclasses.is_dataclass(shape))
        self.assertTrue(registry.frozen)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            shape.records = ()
        self.assertIs(shape.records[0], record)
        self.assertEqual(shape.records, registry.records)
        self.assertEqual(shape.delegations, ())
        self.assertIsInstance(shape.conditions, tuple)
        self.assertNotIsInstance(shape.conditions, ConditionRegistry)
        self.assertIsNot(shape.conditions, registry.conditions)
        self.assertEqual(shape.conditions, ((Document, 'owned', condition),))
        self.assertIs(shape.conditions[0][2], condition)
        registry.conditions._records.clear()
        self.assertEqual(shape.conditions, ((Document, 'owned', condition),))
        self.assertIsInstance(shape.filter_lookup, FrozenConditionLookup)
        self.assertFalse(hasattr(shape.filter_lookup, 'conditions'))
        self.assertIs(
            shape.filter_lookup.record_for(Document, 'owned'), condition,
        )
        self.assertEqual(len(shape.user_rules), 2)
        self.assertTrue(all(isinstance(part, models.Q) for part in shape.user_rules))
        self.assertNotEqual(str(shape.user_rules[0]), str(shape.user_rules[1]))
        self.assertIsNone(shape.override_q)


def _document_models():
    class Document(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class DocumentGrant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Document, DocumentGrant


def _group_models():
    class GroupDocument(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class GroupGrant(models.Model):
        document = models.ForeignKey(GroupDocument, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        group = models.ForeignKey(Group, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return GroupDocument, GroupGrant


def _share_models():
    class ShareDocument(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Share(models.Model):
        document = models.ForeignKey(ShareDocument, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            settings.AUTH_USER_MODEL, related_name='share_delegates',
            on_delete=models.CASCADE,
        )
        sponsor = models.ForeignKey(
            settings.AUTH_USER_MODEL, related_name='share_sponsors',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    return ShareDocument, Share


def _other_grant_models():
    class OtherDocument(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class OtherGrant(models.Model):
        document = models.ForeignKey(OtherDocument, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return OtherDocument, OtherGrant


class CatalogFromShapeTest(TransactionTestCase):
    """A catalog answers from a shape built in the test, not from a factory."""

    def test_shape_answers_and_an_empty_shape_denies(self):
        Scope, Payload, Row, Grant = _prefix_models()
        with connection.schema_editor() as editor:
            editor.create_model(Scope)
            editor.create_model(Payload)
            editor.create_model(Row)
            editor.create_model(Grant)
        try:
            User = get_user_model()
            holder = User.objects.create_user('shape-holder', password='x')
            outsider = User.objects.create_user('shape-outsider', password='x')
            scope = Scope.objects.create(title='scope')
            payload = Payload.objects.create(title='payload')
            Row.objects.create(scope=scope, content=payload)
            content_type = ContentType.objects.get_for_model(Payload)
            read, _created = Permission.objects.get_or_create(
                content_type=content_type, codename='read_shapepayload',
                defaults={'name': 'read'},
            )
            Grant.objects.create(scope=scope, user=holder, permission=read)
            code = '%s.%s' % (content_type.app_label, read.codename)
            factory = RegistryFactory(user_model=User, path='shape-answers')
            grant = Ref(Grant)
            factory.register(
                content=grant.scope.rows.content, user=grant.user,
                permission=grant.permission,
            )
            frozen = factory.build()
            shape = CatalogShape(
                records=frozen.records,
                delegations=frozen.delegations,
                conditions=frozen.conditions,
                user_conditions=frozen.user_conditions,
                user_override=frozen.user_override,
                filter_lookup=frozen.filter_lookup,
                compiler=frozen.compiler,
                cls=frozen.cls,
                path=frozen.path,
                family=frozen.family,
                user_model=frozen.user_model,
                user_rules=frozen.user_rules,
                override_q=frozen.override_q,
            )
            catalog = Catalog(shape)
            self.assertTrue(catalog.has_perm(holder, code, payload))
            self.assertFalse(catalog.has_perm(outsider, code, payload))
            self.assertEqual(
                set(catalog.filter_authorized(
                    Payload.objects.all(), holder, read,
                ).values_list('pk', flat=True)),
                {payload.pk},
            )
            self.assertEqual(
                set(catalog.permitted_users(payload, read).values_list(
                    'pk', flat=True,
                )),
                {holder.pk},
            )
            self.assertEqual(
                set(catalog.filter_by_permitted_content(
                    Scope.objects.all(), holder, read, content=payload,
                ).values_list('pk', flat=True)),
                {scope.pk},
            )
            empty = Catalog(CatalogShape(
                records=(), delegations=(), conditions=(),
                user_conditions=None, user_override=None,
                filter_lookup=FrozenConditionLookup(()),
                compiler=None, cls=RegistryFactory, path='empty-shape',
                family='relationship', user_model=User,
                user_rules=(Q(), Q()), override_q=None,
            ))
            self.assertFalse(empty.has_perm(holder, code, payload))
            self.assertFalse(empty.filter_authorized(
                Payload.objects.all(), holder, read,
            ).exists())
            self.assertEqual(list(empty.permitted_users(payload, read)), [])
            self.assertFalse(empty.filter_by_permitted_content(
                Scope.objects.all(), holder, read, content=payload,
            ).exists())
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Grant)
                editor.delete_model(Row)
                editor.delete_model(Payload)
                editor.delete_model(Scope)
            forget_models(Grant, Row, Payload, Scope)


def _prefix_models():
    class ShapeScope(models.Model):
        title = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    class ShapePayload(models.Model):
        title = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    class ShapeRow(models.Model):
        scope = models.ForeignKey(
            ShapeScope, related_name='rows', on_delete=models.CASCADE,
        )
        content = models.ForeignKey(ShapePayload, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class ShapeGrant(models.Model):
        scope = models.ForeignKey(ShapeScope, on_delete=models.CASCADE)
        user = models.ForeignKey(
            settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return ShapeScope, ShapePayload, ShapeRow, ShapeGrant
