"""Pass 1: ``build_*`` methods return testable shapes without storing.

``RegistryFactory.build_relation``, ``build_delegation``, and
``build_public_registration`` are the pure shape-building halves of
``register``, ``register_delegation``, and ``_register_public``. The
register methods own duplicate/rule checks and append the shapes.
"""

import dataclasses

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.compile.factory import (
    PublicRegistration,
    RegisteredDelegation,
    RegisteredRelation,
    RegistryFactory,
)
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.compile.catalogs import Catalog


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
        self.assertEqual(Catalog(cls=type(registry), path=registry.path, family=registry.family, registry=registry.build_registry()).records, (record,))


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
