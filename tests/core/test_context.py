"""Kernel tests for the registry-driven Context resolution contract (#39).

Uses real test-only database models (``ContextScope`` / ``ContextDocument``
/ ``ContextAttachment`` / ``ContextAnnotation`` / ``ContextTrap``).
Malformed variants are isolated so they never enter the process-wide map.
Does not close #39.
"""

import inspect
import os
import subprocess
import sys
from pathlib import Path

from django.contrib.auth.models import Group
from django.core.checks import Error, run_checks
from django.db import models
from django.db.models import Q, UniqueConstraint
from django.test import SimpleTestCase, TestCase, TransactionTestCase

from trusts.checks import (
    CHECK_ID_INVALID_CONTEXT,
    _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT,
    check_context_registry,
)
from trusts.context import (
    KIND_DIRECT,
    KIND_RELATED,
    Context,
    ContextAdapter,
    ContextNotRegistered,
    ContextRegistrationError,
    ContextRegistry,
    ContextRegistryFrozen,
    check_registration,
)
from trusts.zero.models import (
    Content,
    InvalidContentFieldlookup,
    Junction,
    Trust,
    prepare_context_registry,
)
from trusts.utils import get_short_model_name
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
    Ticket,
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
        from trusts.zero.models import Junction as PublicJunction
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

    def test_public_register_content_cannot_mutate_frozen_registry(self):
        # Exact reproduction from the PR review: after prepare_context_registry()
        # freezes Context, Content.register_content() must not add an adapter
        # while leaving is_frozen() True.
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))
        self.assertFalse(Content.is_content_model(UnregisteredReceiptNote))

        lookup = Content.compose_content_fieldlookup(Receipt, 'notes')
        with self.assertRaises(ContextRegistryFrozen):
            Content.register_content(UnregisteredReceiptNote, lookup)

        self.assertTrue(Context.is_frozen())
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))
        self.assertFalse(Content.is_content_model(UnregisteredReceiptNote))

    def test_late_content_subclass_does_not_mutate_frozen_registry(self):
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))

        class LateReceiptNote(Content):
            receipt = models.ForeignKey(
                Receipt, related_name='late_notes', on_delete=models.CASCADE,
            )
            notes = models.TextField()

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        self.assertTrue(Context.is_frozen())
        self.assertFalse(Context.is_registered(LateReceiptNote))
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))
        self.assertFalse(Content.is_content_model(LateReceiptNote))

    def test_public_junction_registration_is_idempotent_after_freeze(self):
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())
        self.assertTrue(Context.is_registered(TestGroupJunction))
        Junction.register_junction(TestGroupJunction)
        Content.register_content(Receipt)
        self.assertTrue(Context.is_registered(TestGroupJunction))
        self.assertTrue(Context.is_registered(Group))
        self.assertTrue(Context.is_registered(Receipt))

    def test_frozen_junction_idempotence_verifies_identity(self):
        # Exact reproduction: TestGroupJunction is registered for Group,
        # not Receipt. After freeze a contradictory content_model must
        # raise without mutating either adapter.
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())
        junction = Context.get(TestGroupJunction)
        group = Context.get(Group)
        receipt = Context.get(Receipt)
        self.assertEqual(junction.kind, KIND_DIRECT)
        self.assertEqual(group.kind, KIND_RELATED)
        self.assertEqual(receipt.kind, KIND_DIRECT)

        with self.assertRaises(ContextRegistrationError):
            Junction.register_junction(TestGroupJunction, content_model=Receipt)

        self.assertTrue(Context.is_frozen())
        self.assertTrue(Context.get(TestGroupJunction).equivalent(junction))
        self.assertTrue(Context.get(Group).equivalent(group))
        self.assertTrue(Context.get(Receipt).equivalent(receipt))
        self.assertEqual(Context.get(Group).kind, KIND_RELATED)
        self.assertEqual(Context.get(Receipt).kind, KIND_DIRECT)

    def test_public_junction_registration_rejects_new_adapter_after_freeze(self):
        prepare_context_registry()
        self.assertTrue(Context.is_frozen())

        class LateGroup(models.Model):
            name = models.CharField(max_length=32)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        class LateGroupJunction(Junction):
            content = models.OneToOneField(LateGroup, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with self.assertRaises(ContextRegistryFrozen):
            Junction.register_junction(LateGroupJunction)
        self.assertTrue(Context.is_frozen())
        self.assertFalse(Context.is_registered(LateGroupJunction))
        self.assertFalse(Context.is_registered(LateGroup))

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

    def test_finalizers_run_once_before_freeze(self):
        registry = ContextRegistry()
        calls = []

        def fin():
            calls.append(1)
            registry.register_direct(ContextTrap, scope_field='scope')

        registry.add_finalizer(fin)
        registry.ensure_frozen()
        self.assertTrue(registry.is_frozen())
        self.assertTrue(registry.is_registered(ContextTrap))
        registry.ensure_frozen()
        registry.freeze()
        self.assertEqual(calls, [1])
        with self.assertRaises(ContextRegistryFrozen):
            registry.add_finalizer(lambda: None)

    def test_finalizer_failure_does_not_keep_partial_map(self):
        registry = ContextRegistry()
        registry.register_direct(ContextDocument, scope_field='scope')

        def fin():
            registry.register_related(ContextAttachment, through='document')
            raise RuntimeError('finalizer failed')

        registry.add_finalizer(fin)
        with self.assertRaises(RuntimeError):
            registry.filter_by_scope(ContextDocument.objects.none(), [])
        self.assertFalse(registry.is_frozen())
        self.assertTrue(registry.is_registered(ContextDocument))
        self.assertFalse(registry.is_registered(ContextAttachment))
        self.assertEqual(len(registry._finalizers), 1)

    def test_query_paths_run_registry_finalizers(self):
        registry = ContextRegistry()
        registry.register_direct(ContextTrap, scope_field='scope')
        calls = []
        registry.add_finalizer(lambda: calls.append('fin'))
        registry.filter_by_scope(ContextTrap.objects.none(), [])
        self.assertEqual(calls, ['fin'])
        self.assertTrue(registry.is_frozen())


class ContextFreshProcessFreezeTest(SimpleTestCase):
    def test_filter_by_scope_finalizes_pending_before_freeze(self):
        # Exact fresh-process ordering from the PR review: after
        # django.setup(), Group is only pending. A public Context query
        # must run the registered finalizer before freeze so prepare
        # cannot skip it.
        root = Path(__file__).resolve().parents[2]
        env = os.environ.copy()
        env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
        env['PYTHONPATH'] = os.pathsep.join(
            [str(root)] + ([env['PYTHONPATH']] if env.get('PYTHONPATH') else [])
        )
        script = r'''
import django
django.setup()
from django.contrib.auth.models import Group
from tests.models import ContextDocument
from trusts.context import Context
from trusts.zero.models import Content, prepare_context_registry

assert not Context.is_frozen()
assert Content._pending_related
assert not Context.is_registered(Group)

Context.filter_by_scope(ContextDocument.objects.all(), [])

assert Context.is_frozen()
assert Context.is_registered(Group)
assert not any(model is Group for model, _through in Content._pending_related)

prepare_context_registry()
assert Context.is_registered(Group)
print('ok')
'''
        proc = subprocess.run(
            [sys.executable, '-c', script],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('ok', proc.stdout)


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

    def test_many_valued_and_cyclic_fail_closed(self):
        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_direct(Trust, scope_field='groups')
        self.assertIn('many-valued', str(ctx.exception))

        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(
                Trust, through=Content.direct_content_fieldlookup(Receipt),
            )
        self.assertIn('many-valued', str(ctx.exception))

        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_related(Trust, through='trust')
        self.assertIn('cyclic', str(ctx.exception))

        self.assertIsNotNone(check_registration(Trust, KIND_DIRECT, 'groups'))
        self.assertIsNotNone(check_registration(Trust, KIND_RELATED, 'trust'))

    def test_duplicate_different_path_rejected(self):
        registry = ContextRegistry()
        registry.register_direct(Ticket, scope_field='trust')
        registry.register_direct(Ticket, scope_field='trust')
        with self.assertRaises(ContextRegistrationError) as ctx:
            registry.register_direct(Ticket, scope_field='owner')
        self.assertIn('already registered', str(ctx.exception))

    def test_plus_related_name_is_rejected_as_non_invertible(self):
        class HiddenRelatedNameScope(models.Model):
            parent = models.ForeignKey(
                ContextScope,
                related_name='+',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        registry = ContextRegistry()
        with self.assertRaises(ContextRegistrationError) as raised:
            registry.register_direct(HiddenRelatedNameScope, scope_field='parent')
        self.assertIn('invertible', str(raised.exception))
        self.assertIn("'+'", str(raised.exception))

        err = check_registration(
            HiddenRelatedNameScope, KIND_DIRECT, 'parent',
        )
        self.assertIsInstance(err, ContextRegistrationError)
        self.assertIn('invertible', str(err))

        prepare_context_registry()
        key = HiddenRelatedNameScope._meta.concrete_model
        Context.registry._adapters[key] = ContextAdapter(
            KIND_DIRECT, HiddenRelatedNameScope, 'parent', Context.registry,
        )
        try:
            messages = check_context_registry(None)
            e006 = [
                m for m in messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is HiddenRelatedNameScope
            ]
            self.assertEqual(len(e006), 1)
            self.assertEqual(e006[0].id, 'trusts.E006')
            self.assertEqual(e006[0].hint, _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT)
            self.assertIn('invertible', e006[0].msg)
        finally:
            Context.registry._adapters.pop(key, None)

    def test_unusable_reverse_query_names_are_rejected(self):
        cases = (
            ('DoubleUnderscoreReverse', 'bad__path'),
            ('TrailingUnderscoreReverse', 'bad_'),
        )
        for class_name, related_name in cases:
            model = type(class_name, (models.Model,), {
                'parent': models.ForeignKey(
                    ContextScope,
                    related_name=related_name,
                    on_delete=models.CASCADE,
                ),
                'Meta': type('Meta', (), {
                    'app_label': 'trusts_tests',
                    'managed': False,
                }),
                '__module__': __name__,
            })
            registry = ContextRegistry()
            with self.assertRaises(ContextRegistrationError) as raised:
                registry.register_direct(model, scope_field='parent')
            self.assertIn('invertible', str(raised.exception))
            self.assertIn(related_name, str(raised.exception))

            err = check_registration(model, KIND_DIRECT, 'parent')
            self.assertIsInstance(err, ContextRegistrationError)
            self.assertIn('invertible', str(err))

            prepare_context_registry()
            key = model._meta.concrete_model
            Context.registry._adapters[key] = ContextAdapter(
                KIND_DIRECT, model, 'parent', Context.registry,
            )
            try:
                messages = check_context_registry(None)
                e006 = [
                    m for m in messages
                    if m.id == CHECK_ID_INVALID_CONTEXT and m.obj is model
                ]
                self.assertEqual(len(e006), 1)
                self.assertEqual(e006[0].id, 'trusts.E006')
                self.assertIn('invertible', e006[0].msg)
                self.assertEqual(
                    e006[0].hint, _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT,
                )
            finally:
                Context.registry._adapters.pop(key, None)

    def test_partial_unique_constraint_is_not_single_valued(self):
        class PartialUniqueChild(models.Model):
            parent = models.ForeignKey(
                ContextScope,
                related_name='partial_unique_children',
                on_delete=models.CASCADE,
            )
            active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'
                managed = False
                constraints = [
                    UniqueConstraint(
                        fields=['parent'],
                        condition=Q(active=True),
                        name='partial_unique_active_parent',
                    ),
                ]

        registry = ContextRegistry()
        registry.register_direct(PartialUniqueChild, scope_field='parent')
        with self.assertRaises(ContextRegistrationError) as raised:
            registry.register_related(
                ContextScope, through='partial_unique_children',
            )
        self.assertIn('many-valued', str(raised.exception))

        err = check_registration(
            ContextScope, KIND_DIRECT, 'partial_unique_children',
        )
        self.assertIsInstance(err, ContextRegistrationError)
        self.assertIn('many-valued', str(err))

        prepare_context_registry()
        key = ContextScope._meta.concrete_model
        saved = Context.registry._adapters.get(key)
        Context.registry._adapters[key] = ContextAdapter(
            KIND_DIRECT, ContextScope, 'partial_unique_children',
            Context.registry,
        )
        try:
            messages = check_context_registry(None)
            e006 = [
                m for m in messages
                if m.id == CHECK_ID_INVALID_CONTEXT and m.obj is ContextScope
            ]
            self.assertEqual(len(e006), 1)
            self.assertEqual(e006[0].id, 'trusts.E006')
            self.assertIn('many-valued', e006[0].msg)
            self.assertEqual(e006[0].hint, _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT)
        finally:
            if saved is None:
                Context.registry._adapters.pop(key, None)
            else:
                Context.registry._adapters[key] = saved


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

    def test_installed_invalid_declaration_emits_trusts_e006(self):
        # Ticket is a leaf adapter: a stale scalar path must produce
        # exactly one trusts.E006 without also invalidating dependents.
        prepare_context_registry()
        registry = Context.registry
        key = Ticket._meta.concrete_model
        saved = registry._adapters[key]
        registry._adapters[key] = ContextAdapter(
            KIND_DIRECT, Ticket, 'title', registry,
        )
        try:
            messages = check_context_registry(None)
            e006 = [m for m in messages if m.id == CHECK_ID_INVALID_CONTEXT]
            self.assertEqual(len(e006), 1)
            self.assertEqual(e006[0].id, 'trusts.E006')
            self.assertIsInstance(e006[0], Error)
            self.assertIs(e006[0].obj, Ticket)
            self.assertEqual(e006[0].hint, _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT)
            self.assertIn('scalar', e006[0].msg)
            self.assertIn('fail-closed', e006[0].hint)
        finally:
            registry._adapters[key] = saved

        restored = check_context_registry(None)
        self.assertFalse(
            any(m.id == CHECK_ID_INVALID_CONTEXT for m in restored)
        )

    def test_invalid_pending_content_lookup_emits_trusts_e006(self):
        # End-to-end compatibility pipeline: a Trust-origin lookup left in
        # Content._contents (as if deferred while models were loading)
        # must not abort prepare, must emit trusts.E006, and must stay
        # fail-closed at authorization time.
        short = get_short_model_name(UnregisteredReceiptNote)
        invalid = '%s__title' % Content.get_content_fieldlookup(Receipt)
        self.assertFalse(Context.is_registered(UnregisteredReceiptNote))
        self.assertNotIn(short, Content._contents)
        Content._contents[short] = invalid
        Context.registry._frozen = False
        try:
            prepare_context_registry()
            self.assertTrue(Context.is_frozen())
            self.assertFalse(Context.is_registered(UnregisteredReceiptNote))
            self.assertEqual(Content._contents[short], invalid)

            messages = check_context_registry(None)
            e006 = [
                m for m in messages
                if m.id == CHECK_ID_INVALID_CONTEXT
                and m.obj is UnregisteredReceiptNote
            ]
            self.assertEqual(len(e006), 1)
            self.assertEqual(e006[0].id, 'trusts.E006')
            self.assertIsInstance(e006[0], Error)
            self.assertIs(e006[0].obj, UnregisteredReceiptNote)
            self.assertEqual(e006[0].hint, _SILENCE_DOES_NOT_ENABLE_CONTEXT_HINT)
            self.assertIn('fail-closed', e006[0].hint)

            with self.assertRaises(ContextNotRegistered):
                Context.scope_path(UnregisteredReceiptNote)
            with self.assertRaises(InvalidContentFieldlookup):
                Content.require_valid_content_fieldlookup(
                    UnregisteredReceiptNote, invalid,
                )
        finally:
            Content._contents.pop(short, None)
            Context.registry.freeze()


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
        from trusts.zero.models import TrustUserPermission
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

    def test_permitted_is_one_list_query_after_permission_resolve(self):
        Receipt.objects.get_permission('read')
        # Permission natural-key lookup is a separate query from the list
        # filter. The registered resolution itself stays one SQL filter.
        with self.assertNumQueries(2):
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
