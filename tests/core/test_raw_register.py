"""New Pass 1: register stores RAW; lowering happens at build/read.

``register`` keeps only path (refs), the models-tree root, and the
already-lowered condition/along (builders invoked once, discarded).
It does not resolve ``_meta`` paths, construct lowered records, or
check duplicates. ``build_registry()`` / ``records`` lower in
registration order and raise those errors there.
"""

from django.conf import settings
from django.contrib.auth.models import Permission
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.compile.factory import (
    PublicRegistration,
    RawDelegation,
    RawRelation,
    RegisteredRelation,
)
from trusts.core import Ref, TrustsRegistry
from trusts.errors import TrustsConfigurationError


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


def _share_models():
    class ShareDocument(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Share(models.Model):
        document = models.ForeignKey(ShareDocument, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            settings.AUTH_USER_MODEL, related_name='raw_share_delegates',
            on_delete=models.CASCADE,
        )
        sponsor = models.ForeignKey(
            settings.AUTH_USER_MODEL, related_name='raw_share_sponsors',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    return ShareDocument, Share


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RawRegisterTest(SimpleTestCase):
    def test_register_stores_raw_without_resolution(self):
        _Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)

        # 'missing' is not a field on DocumentGrant: resolution would
        # fail, symbolic validation does not look it up.
        raw = registry.register(
            content=root.missing, user=root.user,
            permission=root.permission,
        )

        self.assertIsInstance(raw, RawRelation)
        self.assertEqual(raw.content, Ref(DocumentGrant, ('missing',)))
        self.assertEqual(registry._order, [raw])
        with self.assertRaises(TrustsConfigurationError):
            registry.build_registry()
        with self.assertRaises(TrustsConfigurationError):
            registry.records

    def test_build_lowers_correctly_and_identity_is_stable(self):
        Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)
        kwargs = dict(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        registry.register(**kwargs)

        built = registry.build_relation(**kwargs)
        self.assertIsInstance(built, RegisteredRelation)
        self.assertIs(built.content_model, Document)
        self.assertEqual(registry.records, (built,))
        # Identity memo: repeated reads / builds share lowered objects.
        self.assertIs(registry.records[0], registry.records[0])
        self.assertIs(
            registry.plan_for(Document).records[0], registry.records[0],
        )
        self.assertIs(
            registry.build_registry().records[0], registry.records[0],
        )

    def test_register_after_build_invalidates_not_seals(self):
        _Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)
        registry.register(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        first = registry.build_registry().records
        self.assertEqual(len(first), 1)

        # A second, different-content registration needs a second root;
        # use same bindings with a different closed condition is not
        # available here, so register a delegation-free duplicate check
        # via a new registry path: same registry, second root model.
        _Doc2, Share = _share_models()
        share = Ref(Share)
        registry.register_delegation(
            content=share.document, delegate=share.delegate,
            sponsor=share.sponsor,
        )
        built = registry.build_registry()
        self.assertEqual(built.records, first)
        self.assertEqual(len(built.delegations), 1)
        # A new raw registration invalidates the memo, so lowered
        # objects are rebuilt (equal, not identical); identity is
        # stable across reads at one raw version:
        self.assertIs(built.records[0], registry.records[0])

    def test_duplicate_raises_at_build_with_same_message(self):
        _Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)
        kwargs = dict(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        registry.register(**kwargs)
        registry.register(**kwargs)  # raw: no duplicate check yet

        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.build_registry()
        self.assertIn('Duplicate registration for', str(ctx.exception))

    def test_public_register_stores_public_registration_raw(self):
        _Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()

        shape = registry._register_public(
            trust=DocumentGrant, content='missing', user='user',
            permission='permission',
        )
        self.assertIsInstance(shape, PublicRegistration)
        with self.assertRaises(TrustsConfigurationError):
            registry.records

    def test_raw_delegation_stores_without_resolution(self):
        _Doc, Share = _share_models()
        registry = TrustsRegistry()
        root = Ref(Share)
        raw = registry.register_delegation(
            content=root.missing, delegate=root.delegate,
            sponsor=root.sponsor,
        )
        self.assertIsInstance(raw, RawDelegation)
        with self.assertRaises(TrustsConfigurationError):
            registry.delegations


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RawSymbolicValidationTest(SimpleTestCase):
    def test_symbolic_condition_grammar_stays_at_register(self):
        _Document, DocumentGrant = _document_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)

        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=root.document, user=root.user,
                permission=root.permission, condition=object(),
            )
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=root.document, user=root.user,
                permission=root.permission, along=('not-an-along', 2),
            )
        self.assertEqual(registry._order, [])

    def test_direct_delegation_condition_symbolic_and_lowering(self):
        from trusts.compile.nodes import Equal

        _Doc, Share = _share_models()
        registry = TrustsRegistry()
        root = Ref(Share)
        condition = Equal(root.delegate, root.sponsor)
        raw = registry.register_delegation(
            content=root.document, delegate=root.delegate,
            sponsor=root.sponsor, condition=condition,
        )
        self.assertIsInstance(raw, RawDelegation)
        self.assertEqual(registry.delegations[0].condition, condition)

        with self.assertRaises(TrustsConfigurationError):
            registry.register_delegation(
                content=root.document, delegate=root.delegate,
                sponsor=root.sponsor, condition=object(),
            )

    def test_lowered_helpers_and_root_lookups(self):
        Document, DocumentGrant = _document_models()
        _Doc, Share = _share_models()
        registry = TrustsRegistry()
        root = Ref(DocumentGrant)
        registry.register(
            content=root.document, user=root.user,
            permission=root.permission,
        )
        share = Ref(Share)
        registry.register_delegation(
            content=share.document, delegate=share.delegate,
            sponsor=share.sponsor,
        )

        self.assertEqual(
            registry.records_for_root(DocumentGrant), registry.records,
        )
        self.assertEqual(
            registry.delegations_for_root(Share), registry.delegations,
        )
        with self.assertRaises(TrustsConfigurationError):
            registry.records_for_root(Share)
        with self.assertRaises(TrustsConfigurationError):
            registry.delegations_for_root(DocumentGrant)
        self.assertEqual(registry._records_for(Document), registry.records)
        self.assertEqual(
            registry._delegations_for(_Doc), registry.delegations,
        )
        self.assertEqual(registry._records_for(Document, user_model=None), registry.records)

    def test_public_group_registration_lowers_with_compiler_hop(self):
        from django.contrib.auth.models import Group

        class GroupDocument(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class GroupGrant(models.Model):
            document = models.ForeignKey(
                GroupDocument, on_delete=models.CASCADE,
            )
            user = models.ForeignKey(
                settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
            )
            group = models.ForeignKey(Group, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        registry = TrustsRegistry()
        shape = registry._register_public(
            trust=GroupGrant, content='document', user='user', group='group',
        )
        self.assertIsInstance(shape, PublicRegistration)
        record = registry.records[0]
        self.assertTrue(record.via_group)
        self.assertEqual(record.permission_path, ('group', 'permissions'))
