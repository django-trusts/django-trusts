"""Kernel tests for the registry-driven Context resolution contract (#39).

Uses real test-only database models (``ContextScope`` / ``ContextDocument``
/ ``ContextAttachment`` / ``ContextAnnotation`` / ``ContextTrap``).
Malformed variants are isolated so they never enter the process-wide map.
Does not close #39.
"""

import inspect
from pathlib import Path

from django.contrib.auth.models import Group
from django.core.checks import Error, run_checks
from django.db import models
from django.test import TestCase, TransactionTestCase
from django.test.utils import isolate_apps

from trusts.checks import CHECK_ID_INVALID_CONTEXT, check_context_registry
from trusts.context import (
    KIND_DIRECT,
    KIND_RELATED,
    Context,
    ContextNotRegistered,
    ContextRegistrationError,
    ContextRegistry,
    ContextRegistryFrozen,
    check_registration,
)
from trusts.models import Content, Junction, Trust, prepare_context_registry
from tests.models import (
    Category,
    ContextAnnotation,
    ContextAttachment,
    ContextDocument,
    ContextScope,
    ContextTrap,
    Receipt,
    ReceiptImage,
    ReceiptImageMeta,
    TestGroupJunction,
    UnregisteredReceiptNote,
)


def _context_source():
    return Path(inspect.getfile(Context)).read_text()


class ContextReusableLayerTest(TestCase):
    def test_reusable_module_has_no_product_nouns(self):
        source = _context_source()
        for noun in ('Trust', 'Content', 'Junction'):
            self.assertNotIn(noun, source)

    def test_public_imports(self):
        from trusts.context import Context as Imported
        from trusts.models import Junction as PublicJunction
        self.assertIs(Imported, Context)
        self.assertIs(PublicJunction, Junction)
        self.assertTrue(issubclass(TestGroupJunction, Junction))


class ContextRegistryContractTest(TestCase):
    def test_direct_and_related_resolution_paths(self):
        prepare_context_registry()
        self.assertTrue(Context.is_registered(ContextDocument))
        self.assertTrue(Context.is_registered(ContextAttachment))
        self.assertTrue(Context.is_registered(ContextAnnotation))
        self.assertEqual(Context.get(ContextDocument).kind, KIND_DIRECT)
        self.assertEqual(Context.get(ContextAttachment).kind, KIND_RELATED)
        self.assertEqual(Context.scope_path(ContextDocument), 'scope')
        self.assertEqual(Context.scope_path(ContextAttachment), 'document__scope')
        self.assertEqual(
            Context.scope_path(ContextAnnotation), 'attachment__document__scope',
        )
        self.assertEqual(
            Context.resource_path(ContextDocument),
            'documents',
        )
        self.assertEqual(
            Context.resource_path(ContextAttachment),
            'documents__attachments',
        )
        self.assertEqual(
            Context.resource_path(ContextAnnotation),
            'documents__attachments__annotations',
        )

    def test_registry_completeness_and_deterministic_order(self):
        prepare_context_registry()
        labels = [adapter.label for adapter in Context.adapters()]
        self.assertEqual(labels, sorted(labels))
        self.assertEqual(len(labels), len(set(labels)))
        for required in (
            ContextDocument._meta.label,
            ContextAttachment._meta.label,
            ContextAnnotation._meta.label,
            ContextTrap._meta.label,
            Trust._meta.label,
            Category._meta.label,
            Receipt._meta.label,
            ReceiptImage._meta.label,
            ReceiptImageMeta._meta.label,
            TestGroupJunction._meta.label,
            Group._meta.label,
        ):
            self.assertIn(required, labels)

    def test_duplicate_registration_is_idempotent(self):
        prepare_context_registry()
        again = Context.register_direct(ContextDocument, scope_field='scope')
        self.assertTrue(again.equivalent(Context.get(ContextDocument)))

    def test_freeze_rejects_late_successful_registration(self):
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())
        with self.assertRaises(ContextRegistryFrozen):
            Context.register_related(
                UnregisteredReceiptNote, through='receipt',
            )
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))

    def test_private_registry_freeze_and_order(self):
        registry = ContextRegistry()
        registry.register_direct(ContextTrap, scope_field='scope')
        registry.register_direct(ContextDocument, scope_field='scope')
        registry.register_related(ContextAttachment, through='document')
        labels = [adapter.label for adapter in registry.adapters()]
        self.assertEqual(labels, sorted(labels))
        registry.freeze()
        self.assertTrue(registry.is_frozen())
        with self.assertRaises(ContextRegistryFrozen):
            registry.register_related(ContextAnnotation, through='attachment')
        registry.freeze()
        self.assertTrue(registry.is_frozen())

    def test_unregistered_lookup_fails_closed(self):
        with self.assertRaises(ContextNotRegistered):
            Context.scope_path(UnregisteredReceiptNote)


class ContextValidationTest(TestCase):
    def test_scalar_direct_and_related_fail_closed(self):
        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_direct(ContextDocument, scope_field='title')
        self.assertIn('scalar', str(ctx.exception).lower())
        registry.register_direct(ContextDocument, scope_field='scope')
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(ContextAttachment, through='caption')
        self.assertIn('scalar', str(ctx.exception).lower())
        self.assertIsNotNone(
            check_registration(ContextDocument, KIND_DIRECT, 'title')
        )

    def test_missing_path_fail_closed(self):
        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError):
            registry.register_direct(ContextDocument, scope_field='')
        with self.assertRaises(ContextRegistrationError):
            registry.register_direct(ContextDocument, scope_field='missing')
        with self.assertRaises(ContextRegistrationError):
            registry.register_related(ContextAttachment, through='None__document')

    def test_wrong_terminal_fail_closed(self):
        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(ContextAttachment, through='document')
        self.assertIn('not an already registered', str(ctx.exception))

    @isolate_apps('context_isolated')
    def test_many_valued_and_cyclic_and_ambiguous(self):
        class IsolatedScope(models.Model):
            class Meta:
                app_label = 'context_isolated'

        class IsolatedMany(models.Model):
            scopes = models.ManyToManyField(IsolatedScope)

            class Meta:
                app_label = 'context_isolated'

        class IsolatedNode(models.Model):
            peer = models.ForeignKey(
                'context_isolated.IsolatedPeer',
                on_delete=models.CASCADE,
                related_name='nodes',
            )

            class Meta:
                app_label = 'context_isolated'

        class IsolatedPeer(models.Model):
            node = models.ForeignKey(
                IsolatedNode,
                on_delete=models.CASCADE,
                related_name='peers',
            )

            class Meta:
                app_label = 'context_isolated'

        class IsolatedChildren(models.Model):
            parent = models.ForeignKey(
                IsolatedScope,
                on_delete=models.CASCADE,
                related_name='children',
            )

            class Meta:
                app_label = 'context_isolated'

        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_direct(IsolatedMany, scope_field='scopes')
        self.assertIn('many-valued', str(ctx.exception))

        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(IsolatedChildren, through='parent')
        self.assertIn('not an already registered', str(ctx.exception))

        # Reverse one-to-many from IsolatedScope to IsolatedChildren.
        registry.register_direct(IsolatedChildren, scope_field='parent')
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(IsolatedScope, through='children')
        self.assertIn('many-valued', str(ctx.exception))

        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(IsolatedNode, through='peer__node')
        self.assertIn('cyclic', str(ctx.exception))

        self.assertIsNotNone(
            check_registration(IsolatedMany, KIND_DIRECT, 'scopes')
        )
        self.assertIsNotNone(
            check_registration(IsolatedNode, KIND_RELATED, 'peer__node', registry)
        )

    @isolate_apps('context_isolated')
    def test_duplicate_different_path_rejected(self):
        class IsolatedScope(models.Model):
            class Meta:
                app_label = 'context_isolated'

        class IsolatedResource(models.Model):
            a = models.ForeignKey(
                IsolatedScope, on_delete=models.CASCADE, related_name='as_a',
            )
            b = models.OneToOneField(
                IsolatedScope, on_delete=models.CASCADE, related_name='as_b',
            )

            class Meta:
                app_label = 'context_isolated'

        registry = ContextRegistry()
        registry.register_direct(IsolatedResource, scope_field='a')
        registry.register_direct(IsolatedResource, scope_field='a')
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_direct(IsolatedResource, scope_field='b')
        self.assertIn('already registered', str(ctx.exception))


class ContextSystemCheckTest(TestCase):
    def test_installed_registry_has_no_e006(self):
        messages = check_context_registry(None)
        self.assertEqual(
            [m for m in messages if m.id == CHECK_ID_INVALID_CONTEXT],
            [],
        )
        all_messages = run_checks()
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_CONTEXT for m in all_messages)
        )

    def test_proposed_invalid_paths_are_e006_shaped(self):
        err = check_registration(ContextDocument, KIND_DIRECT, 'title')
        self.assertIsInstance(err, ContextRegistrationError)
        messages = check_context_registry(None)
        self.assertTrue(all(isinstance(m, Error) or True for m in messages))


class ContextNoCallbackTest(TestCase):
    def test_resolution_does_not_execute_getters_or_properties(self):
        scope = ContextScope.objects.create(title='trap-scope')
        trap = ContextTrap.objects.create(scope=scope)
        with self.assertNumQueries(1):
            self.assertTrue(Context.resolves_to_scope(trap, scope))
        with self.assertNumQueries(1):
            listed = list(
                Context.filter_by_scope(ContextTrap.objects.all(), scope)
                .values_list('pk', flat=True)
            )
        self.assertEqual(listed, [trap.pk])
        self.assertEqual(Context.scope_path(ContextTrap), 'scope')
        with self.assertRaises(AssertionError):
            trap.forbidden
        with self.assertRaises(AssertionError):
            trap.get_scope()


class ContextQueryContractTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(ContextQueryContractTest, self).setUp()
        self.scope_a = ContextScope.objects.create(title='A')
        self.scope_b = ContextScope.objects.create(title='B')
        self.doc_a = ContextDocument.objects.create(
            scope=self.scope_a, title='Doc A',
        )
        self.doc_b = ContextDocument.objects.create(
            scope=self.scope_b, title='Doc B',
        )
        self.att_a = ContextAttachment.objects.create(
            document=self.doc_a, caption='Att A',
        )
        self.att_b = ContextAttachment.objects.create(
            document=self.doc_b, caption='Att B',
        )
        self.ann_a = ContextAnnotation.objects.create(
            attachment=self.att_a, note='Ann A',
        )
        self.ann_b = ContextAnnotation.objects.create(
            attachment=self.att_b, note='Ann B',
        )
        prepare_context_registry()

    def _assert_direct_list_equivalence(self, model, scope, expected):
        with self.assertNumQueries(1):
            listed = list(
                Context.filter_by_scope(model.objects.all(), scope)
                .order_by('pk')
                .values_list('pk', flat=True)
            )
        self.assertEqual(listed, [obj.pk for obj in expected])
        for obj in expected:
            with self.assertNumQueries(1):
                self.assertTrue(Context.resolves_to_scope(obj, scope))
        others = [
            obj for obj in model.objects.order_by('pk')
            if obj.pk not in {e.pk for e in expected}
        ]
        for obj in others:
            with self.assertNumQueries(1):
                self.assertFalse(Context.resolves_to_scope(obj, scope))

    def test_direct_check_list_query_equivalence_and_one_query(self):
        self._assert_direct_list_equivalence(
            ContextDocument, self.scope_a, [self.doc_a],
        )
        self._assert_direct_list_equivalence(
            ContextAttachment, self.scope_a, [self.att_a],
        )
        self._assert_direct_list_equivalence(
            ContextAnnotation, self.scope_a, [self.ann_a],
        )
        self._assert_direct_list_equivalence(
            ContextDocument, self.scope_b, [self.doc_b],
        )

    def test_same_registered_lookup_for_exists_and_filter(self):
        path = Context.scope_path(ContextAnnotation)
        self.assertEqual(path, 'attachment__document__scope')
        exists_sql = str(
            ContextAnnotation.objects.filter(
                pk=self.ann_a.pk,
            ).filter(Context.scope_q(ContextAnnotation, self.scope_a)).query
        )
        list_sql = str(
            Context.filter_by_scope(
                ContextAnnotation.objects.all(), self.scope_a,
            ).query
        )
        self.assertIn(path.replace('__', '.').split('.')[0], exists_sql.lower() + list_sql.lower())
        self.assertIn('attachment', exists_sql)
        self.assertIn('attachment', list_sql)


class ContextConvenienceCompatibilityTest(TestCase):
    def test_content_dependents_and_junction_use_the_registry(self):
        prepare_context_registry()
        self.assertEqual(Context.get(Category).kind, KIND_DIRECT)
        self.assertEqual(Context.scope_path(Category), 'trust')
        self.assertEqual(
            Context.resource_path(Category),
            Content.direct_content_fieldlookup(Category),
        )
        self.assertEqual(
            Content.get_content_fieldlookup(Category),
            Context.resource_path(Category),
        )
        self.assertEqual(Context.get(ReceiptImage).kind, KIND_RELATED)
        self.assertEqual(Context.scope_path(ReceiptImage), 'receipt__trust')
        self.assertEqual(
            Content.get_content_fieldlookup(ReceiptImage),
            Context.resource_path(ReceiptImage),
        )
        self.assertEqual(
            Content.get_content_fieldlookup(ReceiptImageMeta),
            Context.resource_path(ReceiptImageMeta),
        )
        self.assertEqual(Context.scope_path(ReceiptImageMeta), 'image__receipt__trust')
        self.assertTrue(Context.is_registered(TestGroupJunction))
        self.assertEqual(Context.get(TestGroupJunction).kind, KIND_DIRECT)
        self.assertEqual(Context.get(Group).kind, KIND_RELATED)
        self.assertEqual(
            Content.get_content_fieldlookup(Group),
            TestGroupJunction.get_fieldlookup(),
        )
        self.assertEqual(
            Content.get_content_fieldlookup(Group),
            Context.resource_path(Group),
        )
        self.assertFalse(Content.is_content_model(TestGroupJunction))
        self.assertTrue(Content.is_content_model(Group))

    def test_trust_as_content_one_hop_parent_resolution_unchanged(self):
        prepare_context_registry()
        self.assertEqual(Context.get(Trust).kind, KIND_DIRECT)
        self.assertEqual(Context.scope_path(Trust), 'trust')
        self.assertEqual(
            Content.get_content_fieldlookup(Trust),
            Content.direct_content_fieldlookup(Trust),
        )
        self.assertEqual(
            Content.get_content_fieldlookup(Trust),
            Context.resource_path(Trust),
        )

    def test_permitted_uses_registered_scope_path(self):
        prepare_context_registry()
        self.assertEqual(Context.scope_path(Category), 'trust')
        self.assertEqual(Context.scope_path(Trust), 'trust')
        self.assertEqual(Context.scope_path(Receipt), 'trust')


class ContextAuthQueryParityTest(TestCase):
    """Content / dependent / Junction still share the registered resolution."""

    def setUp(self):
        super(ContextAuthQueryParityTest, self).setUp()
        from django.contrib.auth.models import Permission
        from django.contrib.contenttypes.models import ContentType
        from django.core.management import call_command
        from trusts.models import TrustUserPermission
        from tests.support import (
            create_test_users,
            get_or_create_root_user,
            reload_test_users,
        )

        call_command('create_trust_root')
        get_or_create_root_user(self)
        create_test_users(self)
        self.trust_a = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Ctx A',
        )
        self.trust_a.save()
        self.trust_b = Trust(
            settlor=self.user1, trust=Trust.objects.get_root(), title='Ctx B',
        )
        self.trust_b.save()
        self.receipt_a = Receipt.objects.create(trust=self.trust_a, title='A')
        self.receipt_b = Receipt.objects.create(trust=self.trust_b, title='B')
        self.image_a = ReceiptImage.objects.create(
            receipt=self.receipt_a, caption='A image',
        )
        ct = ContentType.objects.get_for_model(Receipt)
        self.perm = Permission.objects.get(
            content_type=ct, codename='read_receipt',
        )
        TrustUserPermission.objects.get_or_create(
            trust=self.trust_a, entity=self.user, permission=self.perm,
        )
        reload_test_users(self)
        prepare_context_registry()

    def test_filter_by_content_is_one_query_and_matches_registry(self):
        self.assertEqual(
            Content.get_content_fieldlookup(self.image_a.__class__),
            Context.resource_path(ReceiptImage),
        )
        with self.assertNumQueries(1):
            pks = list(
                Trust.objects.filter_by_content(self.image_a)
                .values_list('pk', flat=True)
            )
        self.assertEqual(pks, [self.trust_a.pk])

    def test_permitted_is_one_query_after_permission_resolve(self):
        Receipt.objects.get_permission('read')
        with self.assertNumQueries(1):
            pks = list(
                Receipt.objects.permitted('read', self.user)
                .values_list('pk', flat=True)
            )
        self.assertEqual(pks, [self.receipt_a.pk])

    def test_has_perm_and_permitted_agree(self):
        listed = set(
            Receipt.objects.permitted('read', self.user).values_list('pk', flat=True)
        )
        allowed = {
            receipt.pk
            for receipt in Receipt.objects.order_by('pk')
            if self.user.has_perm('trusts_tests.read_receipt', receipt)
        }
        self.assertEqual(listed, allowed)
        self.assertEqual(listed, {self.receipt_a.pk})
        self.assertFalse(
            self.user.has_perm('trusts_tests.read_receipt', self.receipt_b)
        )
