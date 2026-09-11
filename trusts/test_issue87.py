"""S7: delete the legacy static content registry (issue #87).

Structural and behavioral tests only — no source-token or
``inspect.getsource`` assertions. Conditions and
``HistoricalGroupQueryCompiler`` stay; the static content map does not.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.apps import AppConfig, apps
from trusts.apps import kernel_config
from django.contrib.auth.models import AnonymousUser, Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection, models
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from tests.apps import clone_writable_registry, forget_models, override_apps_ready
from tests.backends import MixinOnlyBackend
from tests.models import Category, TestGroupJunction, Ticket
from trusts.backends import (
    HistoricalGroupQueryCompiler,
    TrustModelBackend,
    TrustModelBackendMixin,
)
from trusts.checks import check_permission_conditions
from trusts.conditions import condition_refs, validate_expression
from trusts.core import (
    PlanQueryCompiler,
    Ref,
    TrustsRegistry,
    common_permissions,
)
from trusts.models import (
    Content,
    ContentManager,
    Junction,
    Trust,
    TrustManager,
    TrustUserPermission,
    register_content_junction,
)
from trusts.tests import (
    enable_local_group_grant,
    get_or_create_root_user,
)


CONCRETE = 'trusts.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
_u, _p, _o = condition_refs()
_IMPORT_CONDITIONS = {
    name: dict(codes) for name, codes in Content._conditions.items()
}


def _restore_conditions(snapshot):
    Content._conditions.clear()
    for name, codes in snapshot.items():
        Content._conditions[name] = dict(codes)


class _ConditionIsolationMixin(object):
    def setUp(self):
        super().setUp()
        _restore_conditions(_IMPORT_CONDITIONS)

    def tearDown(self):
        _restore_conditions(_IMPORT_CONDITIONS)
        super().tearDown()


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _perm(model, codename):
    ct, _created = ContentType.objects.get_or_create(
        app_label=model._meta.app_label,
        model=model._meta.model_name,
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


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
        all_models = apps.all_models
        for model in model_classes:
            all_models[model._meta.app_label].pop(model._meta.model_name, None)
        apps.clear_cache()


_CHAIN = [0]


def _receipt_chain():
    """Documented Receipt → image → image reverse-O2M encodings."""
    _CHAIN[0] += 1
    n = _CHAIN[0]
    module = _receipt_chain.__module__

    class ReceiptMeta:
        app_label = 'trusts_tests'

    Receipt = type('Receipt%s' % n, (Content,), {
        '__module__': module,
        'title': models.CharField(max_length=40),
        'Meta': ReceiptMeta,
    })

    class ImageMeta:
        app_label = 'trusts_tests'

    ReceiptImage = type('ReceiptImage%s' % n, (models.Model,), {
        '__module__': module,
        'receipt': models.ForeignKey(
            Receipt, related_name='image', on_delete=models.CASCADE,
        ),
        'title': models.CharField(max_length=40),
        'objects': ContentManager(),
        'Meta': ImageMeta,
    })

    class ImageMetaMeta:
        app_label = 'trusts_tests'

    ReceiptImageMeta = type('ReceiptImageMeta%s' % n, (models.Model,), {
        '__module__': module,
        'image': models.ForeignKey(
            ReceiptImage, related_name='image', on_delete=models.CASCADE,
        ),
        'title': models.CharField(max_length=40),
        'objects': ContentManager(),
        'Meta': ImageMetaMeta,
    })

    class OrphanMeta:
        app_label = 'trusts_tests'

    OrphanDoc = type('OrphanDoc%s' % n, (models.Model,), {
        '__module__': module,
        'receipt': models.ForeignKey(
            Receipt, related_name='orphan', on_delete=models.CASCADE,
        ),
        'title': models.CharField(max_length=40),
        'objects': ContentManager(),
        'Meta': OrphanMeta,
    })
    return Receipt, ReceiptImage, ReceiptImageMeta, OrphanDoc


def dependent_content_ref(root_ref, content_model, *suffixes):
    """Bounded S5 path: Trust reverse onto ``content_model``, then suffixes."""
    rev = content_model._meta.get_field('trust').remote_field.get_accessor_name()
    node = getattr(root_ref.trust, rev)
    for name in suffixes:
        node = getattr(node, name)
    return node


class DependentHostConfig(AppConfig):
    """Isolated host AppConfig that contributes both documented levels."""

    name = 'tests'
    label = 'trusts_tests_s7_host'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.holder_model = None

    def ready(self):
        if getattr(self, 'apps', None) is None or not self.apps.is_installed('trusts'):
            return
        if self.holder_model is None:
            return
        registry = kernel_config(self.apps).configured_backend().registry
        j = Ref(TrustUserPermission)
        donated_image = getattr(self, '_trusts_tup_image_registry_id', None)
        if donated_image is not registry:
            registry.register(
                content=dependent_content_ref(j, self.holder_model, 'image'),
                user=j.entity,
                permission=j.permission,
            )
            self._trusts_tup_image_registry_id = registry
        donated_meta = getattr(self, '_trusts_tup_meta_registry_id', None)
        if donated_meta is not registry:
            registry.register(
                content=dependent_content_ref(j, self.holder_model, 'image', 'image'),
                user=j.entity,
                permission=j.permission,
            )
            self._trusts_tup_meta_registry_id = registry


def _new_dependent_host(apps_registry, holder_model):
    contributor = DependentHostConfig('tests', tests_module)
    contributor.apps = apps_registry
    contributor.holder_model = holder_model
    return contributor


class _RegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = kernel_config()
        self.saved_registries = dict(self.live.registries)
        self.saved_trust_sentinel = getattr(
            self.live, '_trusts_tup_trust_registry_id', None
        )
        self.saved_trust_ids = getattr(
            self.live, '_trusts_tup_trust_registry_ids', None
        )

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved_registries)
        self.live._trusts_tup_trust_registry_id = self.saved_trust_sentinel
        if self.saved_trust_ids is None:
            if hasattr(self.live, '_trusts_tup_trust_registry_ids'):
                delattr(self.live, '_trusts_tup_trust_registry_ids')
        else:
            self.live._trusts_tup_trust_registry_ids = self.saved_trust_ids
        super().tearDown()


class _UsersMixin(object):
    def _make_users(self, suffix):
        get_or_create_root_user(self)
        call_command('create_trust_root')
        self.alice = User.objects.create_user(
            'alice-%s' % suffix, 'alice-%s@example.com' % suffix, 'x',
        )
        self.bob = User.objects.create_user(
            'bob-%s' % suffix, 'bob-%s@example.com' % suffix, 'x',
        )
        self.carol = User.objects.create_user(
            'carol-%s' % suffix, 'carol-%s@example.com' % suffix, 'x',
        )
        for user in (self.alice, self.bob, self.carol):
            user.is_active = True
            user.save()
        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='S7 A %s' % suffix)
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='S7 B %s' % suffix)
        self.trust_b.save()

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.bob = User.objects.get(pk=self.bob.pk)
        self.carol = User.objects.get(pk=self.carol.pk)


class LegacyContentRegistryDeletedTest(SimpleTestCase):
    """Runtime structure: the static content map and its writers are gone."""

    def test_no_contents_map_or_lookup_api(self):
        self.assertFalse(hasattr(Content, '_contents'))
        self.assertFalse(hasattr(Content, 'is_content_model'))
        self.assertFalse(hasattr(Content, 'is_content'))
        self.assertFalse(hasattr(Content, 'get_content_fieldlookup'))

    def test_no_filter_by_content_or_get_trusts(self):
        self.assertFalse(hasattr(TrustManager, 'filter_by_content'))
        self.assertFalse(hasattr(Trust.objects, 'filter_by_content'))
        self.assertFalse(hasattr(TrustModelBackendMixin, '_get_trusts'))
        self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
        self.assertFalse(hasattr(TrustModelBackend(), '_get_trusts'))

    def test_register_content_is_conditions_only(self):
        self.assertFalse(hasattr(Content, '_contents'))
        before = dict(Content._conditions)
        try:
            class BareNote(models.Model):
                title = models.CharField(max_length=10)

                class Meta:
                    app_label = 'trusts_tests'
                    managed = False

            Content.register_content(BareNote)
            self.assertFalse(hasattr(Content, '_contents'))
            self.assertFalse(
                kernel_config().registry.plan_for(BareNote).records
            )
        finally:
            Content._conditions.clear()
            Content._conditions.update(before)
            forget_models(BareNote)

    def test_class_prepared_does_not_write_a_content_map(self):
        before = dict(Content._conditions)
        live = kernel_config().registry
        try:
            class IsolatedSheet(Content):
                class Meta:
                    app_label = 'trusts_tests'
                    managed = False
                    permission_conditions = (
                        ('sheet_own', _o.trust != None),
                    )

            self.assertFalse(hasattr(Content, '_contents'))
            self.assertFalse(live.plan_for(IsolatedSheet).records)
            record = Content.get_permission_condition_record(
                IsolatedSheet, 'sheet_own',
            )
            self.assertIsNotNone(record)
            self.assertIs(record.model, IsolatedSheet)
            validate_expression(record.expr, IsolatedSheet)
            register_content_junction(IsolatedSheet)
            self.assertFalse(hasattr(Content, '_contents'))
            self.assertFalse(live.plan_for(IsolatedSheet).records)
        finally:
            Content._conditions.clear()
            Content._conditions.update(before)
            forget_models(IsolatedSheet)

    def test_register_junction_does_not_write_a_content_map(self):
        before = dict(Content._conditions)
        live = kernel_config().registry
        group_before = live.plan_for(Group).records
        try:
            class IsolatedJunction(Junction):
                content = models.ForeignKey(
                    Group, unique=True, on_delete=models.CASCADE,
                )

                class Meta:
                    app_label = 'trusts_tests'
                    managed = False
                    content_permission_conditions = (
                        ('junc_own', _o.trust != None),
                    )

            Junction.register_junction(IsolatedJunction)
            self.assertFalse(hasattr(Content, '_contents'))
            self.assertEqual(live.plan_for(Group).records, group_before)
            record = Content.get_permission_condition_record(
                IsolatedJunction, 'junc_own',
            )
            self.assertIsNotNone(record)
            self.assertIs(record.model, IsolatedJunction)
        finally:
            Content._conditions.clear()
            Content._conditions.update(before)
            forget_models(IsolatedJunction)


class ConditionRegistryPreservedTest(_ConditionIsolationMixin, TestCase):
    def test_trust_own_and_ticket_meta_own_remain(self):
        own = Content.get_permission_condition_record(Trust, 'own')
        self.assertIsNotNone(own)
        self.assertIs(own.model, Trust)
        validate_expression(own.expr, Trust)
        meta_own = Content.get_permission_condition_record(Ticket, 'meta_own')
        self.assertIsNotNone(meta_own)
        self.assertIs(meta_own.model, Ticket)
        validate_expression(meta_own.expr, Ticket)
        messages = check_permission_conditions(None)
        self.assertEqual([m for m in messages if m.id == 'trusts.E001'], [])

    def test_duplicate_condition_overwrites_same_identity(self):
        before = dict(Content._conditions)
        try:
            Content.register_permission_condition(Ticket, 'meta_own', _u == _o.owner)
            record = Content.get_permission_condition_record(Ticket, 'meta_own')
            self.assertIsNotNone(record)
            self.assertIs(record.model, Ticket)
            validate_expression(record.expr, Ticket)
        finally:
            Content._conditions.clear()
            Content._conditions.update(before)


class HistoricalCompilerPreservedTest(SimpleTestCase):
    def test_concrete_compiler_identity_and_mixin_isolation(self):
        self.assertTrue(HistoricalGroupQueryCompiler.historical_fallback)
        self.assertFalse(PlanQueryCompiler.historical_fallback)
        self.assertIsInstance(
            TrustModelBackend.query_compiler, HistoricalGroupQueryCompiler,
        )
        self.assertIsInstance(
            MixinOnlyBackend.query_compiler, PlanQueryCompiler,
        )
        handle = kernel_config().configured_backend()
        self.assertTrue(handle.historical_fallback)
        self.assertIsInstance(handle.compiler, HistoricalGroupQueryCompiler)


class LiveTerminalParityTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('parity')
        self.cat = Category.objects.create(trust=self.trust_a, name='s7-cat')
        self.change_cat = _perm(Category, 'change_category')
        self.cat_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change_cat,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s7-parity')
        self.carol.groups.add(self.carol_group)
        self.change_cat.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change_cat)
        self.group = Group.objects.create(name='s7-protected')
        TestGroupJunction.objects.create(
            trust=self.trust_a, content=self.group, name='s7-j',
        )
        self.change_group = _perm(Group, 'change_group')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change_group,
        ).save()
        self._reload()

    def test_category_ticket_trust_group_allow_deny_unchanged(self):
        self.assertTrue(self.alice.has_perm(self.cat_code, self.cat))
        self.assertTrue(self.carol.has_perm(self.cat_code, self.cat))
        self.assertFalse(self.bob.has_perm(self.cat_code, self.cat))
        self.assertFalse(self.alice.has_perm(self.cat_code))
        qs = Category.objects.filter(pk=self.cat.pk)
        self.assertTrue(self.alice.has_perm(self.cat_code, qs))
        self.assertIn(self.cat_code, self.alice.get_all_permissions(self.cat))
        self.assertNotIn(self.cat_code, self.alice.get_group_permissions(self.cat))
        self.assertIn(self.cat_code, self.carol.get_group_permissions(self.cat))
        self.assertTrue(self.alice.has_perm('auth.change_group', self.group))
        child = Trust(settlor=self.alice, trust=self.trust_a, title='s7-child')
        child.save()
        change_trust = _perm(Trust, 'change_trust')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=change_trust,
        ).save()
        from tests.models import Organization
        org = Organization.objects.create(name='s7-org', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='s7-t', owner=self.alice,
            organization=org, status='open',
        )
        ticket_change = _perm(Ticket, 'change_ticket')
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=ticket_change,
        ).save()
        self._reload()
        self.assertTrue(self.alice.has_perm('trusts.change_trust', child))
        self.assertTrue(self.alice.has_perm('trusts.change_trust:own', child))
        self.assertFalse(self.bob.has_perm('trusts.change_trust', child))
        self.assertTrue(self.alice.has_perm('trusts_tests.change_ticket', ticket))
        self.assertTrue(self.alice.has_perm('trusts_tests.change_ticket:meta_own', ticket))
        self.assertFalse(self.bob.has_perm('trusts_tests.change_ticket', ticket))
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(self.alice.has_perm(self.cat_code, self.cat))
        self.assertFalse(AnonymousUser().has_perm(self.cat_code, self.cat))


class DependentHostContributionTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_reenter_and_per_contribution_sentinels(self):
        Receipt, Image, Meta, _orphan = _receipt_chain()
        isolated = TrustsRegistry()
        self.live.registries[CONCRETE] = isolated
        contributor = _new_dependent_host(apps, Receipt)
        with override_apps_ready(False):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_image_registry_id, isolated)
        self.assertIs(contributor._trusts_tup_meta_registry_id, isolated)
        before = isolated.records
        with patch.object(isolated, 'register', wraps=isolated.register) as register:
            contributor.ready()
        register.assert_not_called()
        self.assertEqual(isolated.records, before)
        self.assertEqual(len(isolated.plan_for(Receipt).records), 0)
        self.assertEqual(len(isolated.plan_for(Image).records), 1)
        self.assertEqual(len(isolated.plan_for(Meta).records), 1)

        isolated_meta = TrustsRegistry()
        self.live.registries[CONCRETE] = isolated_meta
        partial = _new_dependent_host(apps, Receipt)
        partial._trusts_tup_image_registry_id = isolated_meta
        with override_apps_ready(False):
            partial.ready()
        self.assertIs(partial._trusts_tup_image_registry_id, isolated_meta)
        self.assertIs(partial._trusts_tup_meta_registry_id, isolated_meta)
        self.assertEqual(len(isolated_meta.plan_for(Image).records), 0)
        self.assertEqual(len(isolated_meta.plan_for(Meta).records), 1)
        forget_models(Receipt, Image, Meta, _orphan)


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsDoesNotDonateDependentContributionTest(SimpleTestCase):
    def test_isolate_apps_ready_does_not_touch_live_registry(self):
        live = kernel_config().registry
        before = live.records
        Receipt, *_rest = _receipt_chain()
        contributor = DependentHostConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.holder_model = Receipt
        contributor.ready()
        forget_models(Receipt, *_rest)
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_image_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_meta_registry_id', None)
        )
        self.assertEqual(live.records, before)


class DependentAuthorizationTest(_RegistryRestoreMixin, _UsersMixin, TransactionTestCase):
    def setUp(self):
        super().setUp()
        (
            self.Receipt, self.Image, self.Meta, self.Orphan,
        ) = _receipt_chain()
        self._table_cm = _tables(
            self.Receipt, self.Image, self.Meta, self.Orphan,
        )
        self._table_cm.__enter__()
        self._make_users('dep')
        self.receipt_a1 = self.Receipt.objects.create(trust=self.trust_a, title='A1')
        self.receipt_a2 = self.Receipt.objects.create(trust=self.trust_a, title='A2')
        self.receipt_b = self.Receipt.objects.create(trust=self.trust_b, title='B')
        self.img_a1 = self.Image.objects.create(receipt=self.receipt_a1, title='A1')
        self.img_a2 = self.Image.objects.create(receipt=self.receipt_a2, title='A2')
        self.img_b = self.Image.objects.create(receipt=self.receipt_b, title='B')
        self.meta_a1 = self.Meta.objects.create(image=self.img_a1, title='A1')
        self.meta_a2 = self.Meta.objects.create(image=self.img_a2, title='A2')
        self.meta_b = self.Meta.objects.create(image=self.img_b, title='B')
        self.orphan = self.Orphan.objects.create(receipt=self.receipt_a1, title='X')
        extras = [
            self.Image.objects.create(
                receipt=self.Receipt.objects.create(
                    trust=self.trust_a, title='X%s' % i,
                ),
                title='X%s' % i,
            )
            for i in range(6)
        ]
        self.extra_metas = [
            self.Meta.objects.create(image=image, title=image.title)
            for image in extras
        ]
        contributor = _new_dependent_host(apps, self.Receipt)
        writable = clone_writable_registry(self.live.registries[CONCRETE])
        self.live.registries[CONCRETE] = writable
        with override_apps_ready(False):
            contributor.ready()
        self.image_code = 'trusts_tests.change_%s' % self.Image._meta.model_name
        self.meta_code = 'trusts_tests.change_%s' % self.Meta._meta.model_name
        self.orphan_code = 'trusts_tests.change_%s' % self.Orphan._meta.model_name
        self.image_perm = _perm(self.Image, 'change_%s' % self.Image._meta.model_name)
        self.meta_perm = _perm(self.Meta, 'change_%s' % self.Meta._meta.model_name)
        self.orphan_perm = _perm(self.Orphan, 'change_%s' % self.Orphan._meta.model_name)
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.image_perm,
        ).save()
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.meta_perm,
        ).save()
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.orphan_perm,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s7-dep')
        self.carol.groups.add(self.carol_group)
        self.image_perm.group_set.add(self.carol_group)
        self.meta_perm.group_set.add(self.carol_group)
        enable_local_group_grant(
            self.trust_a, self.carol_group, self.image_perm, self.meta_perm,
        )
        self._reload()

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)
        super().tearDown()

    def test_host_contributed_both_documented_levels(self):
        handle = self.live.configured_backend()
        image_plan = handle.registry.plan_for(self.Image)
        meta_plan = handle.registry.plan_for(self.Meta)
        self.assertTrue(image_plan.records)
        self.assertTrue(meta_plan.records)
        rev = self.Receipt._meta.get_field('trust').remote_field.get_accessor_name()
        self.assertEqual(
            image_plan.records[0].content_path, ('trust', rev, 'image'),
        )
        self.assertEqual(
            meta_plan.records[0].content_path, ('trust', rev, 'image', 'image'),
        )
        self.assertFalse(handle.registry.plan_for(self.Orphan).records)
        self.assertFalse(handle.registry.plan_for(self.Receipt).records)

    def test_image_object_queryset_enum_direct_and_group(self):
        self._assert_terminal(
            self.Image, self.image_code,
            self.img_a1, self.img_a2, self.img_b,
        )

    def test_meta_object_queryset_enum_direct_and_group(self):
        self._assert_terminal(
            self.Meta, self.meta_code,
            self.meta_a1, self.meta_a2, self.meta_b,
        )

    def _assert_terminal(self, model, code, granted, sibling, other):
        self.assertTrue(self.alice.has_perm(code, granted))
        self.assertTrue(self.alice.has_perm(code, sibling))
        self.assertFalse(self.alice.has_perm(code, other))
        self.assertFalse(self.bob.has_perm(code, granted))
        self.assertTrue(self.carol.has_perm(code, granted))
        self.assertFalse(self.carol.has_perm(code, other))
        granted_qs = model.objects.filter(pk__in=[granted.pk, sibling.pk])
        mixed_qs = model.objects.filter(pk__in=[granted.pk, other.pk])
        self.assertTrue(self.alice.has_perm(code, granted_qs))
        self.assertFalse(self.alice.has_perm(code, mixed_qs))
        self.assertTrue(self.carol.has_perm(code, granted_qs))
        self.assertFalse(self.carol.has_perm(code, mixed_qs))
        self.assertTrue(self.alice.has_perms((code,), granted))
        self.assertFalse(self.bob.has_perms((code,), granted))
        alice_all = self.alice.get_all_permissions(granted)
        alice_group = self.alice.get_group_permissions(granted)
        self.assertIn(code, alice_all)
        self.assertNotIn(code, alice_group)
        carol_all = self.carol.get_all_permissions(granted)
        carol_group = self.carol.get_group_permissions(granted)
        self.assertIn(code, carol_all)
        self.assertIn(code, carol_group)
        self.assertIn(code, self.alice.get_all_permissions(granted_qs))
        self.assertEqual(self.alice.get_group_permissions(granted_qs), set())
        self.assertIn(code, self.carol.get_group_permissions(granted_qs))
        self.assertEqual(self.bob.get_all_permissions(granted), set())
        handle = self.live.configured_backend()
        common = common_permissions((handle,), granted_qs, self.alice)
        self.assertIsInstance(common, QuerySet)
        self.assertIn(code.split('.', 1)[1], set(common.values_list('codename', flat=True)))
        self.assertEqual(
            list(common_permissions((handle,), mixed_qs, self.alice)),
            [],
        )

    def test_one_sql_independent_of_candidate_count(self):
        image_qs = self.Image.objects.filter(
            pk__in=[self.img_a1.pk, self.img_a2.pk] + [
                image.pk for image in self.Image.objects.exclude(
                    pk__in=[self.img_a1.pk, self.img_a2.pk, self.img_b.pk],
                )
            ],
        )
        meta_qs = self.Meta.objects.filter(
            pk__in=[self.meta_a1.pk, self.meta_a2.pk] + [
                meta.pk for meta in self.extra_metas
            ],
        )
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.image_code, self.img_a1))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.image_code, image_qs))
        with self.assertNumQueries(1):
            self.assertIn(self.image_code, self.alice.get_all_permissions(image_qs))
        with self.assertNumQueries(1):
            self.assertIn(self.image_code, self.carol.get_group_permissions(image_qs))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.meta_code, self.meta_a1))
        with self.assertNumQueries(1):
            self.assertTrue(self.alice.has_perm(self.meta_code, meta_qs))
        with self.assertNumQueries(1):
            self.assertIn(self.meta_code, self.alice.get_all_permissions(meta_qs))
        with self.assertNumQueries(1):
            self.assertIn(self.meta_code, self.carol.get_group_permissions(meta_qs))

    def test_undeclared_orphan_fails_closed_and_never_reaches_old_fallback(self):
        self.assertFalse(hasattr(Content, '_contents'))
        self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
        self.assertFalse(hasattr(Trust.objects, 'filter_by_content'))
        handle = self.live.configured_backend()
        self.assertFalse(handle.registry.plan_for(self.Orphan).records)
        self.assertFalse(self.alice.has_perm(self.orphan_code, self.orphan))
        self.assertFalse(self.carol.has_perm(self.orphan_code, self.orphan))
        qs = self.Orphan.objects.filter(pk=self.orphan.pk)
        self.assertFalse(self.alice.has_perm(self.orphan_code, qs))
        self.assertEqual(self.alice.get_all_permissions(self.orphan), set())
        self.assertEqual(self.alice.get_group_permissions(self.orphan), set())
        self.assertFalse(self.Orphan.objects.permitted(self.orphan_code, self.alice).exists())
        self.assertFalse(
            Trust.objects.filter_by_user_content_perm(
                self.alice, self.Orphan, 'change_orphandoc',
            ).exists()
        )

    def test_inactive_anonymous_obj_none(self):
        self.assertFalse(self.alice.has_perm(self.image_code))
        self.assertEqual(self.alice.get_all_permissions(), set())
        self.alice.is_active = False
        self.alice.save()
        self._reload()
        self.assertFalse(self.alice.has_perm(self.image_code, self.img_a1))
        self.assertFalse(AnonymousUser().has_perm(self.image_code, self.img_a1))
        self.assertEqual(AnonymousUser().get_all_permissions(self.img_a1), set())


class UnknownTerminalFailsClosedTest(_UsersMixin, TestCase):
    def setUp(self):
        super().setUp()
        self._make_users('unk')
        self._reload()

    def test_unknown_user_and_dict_fail_closed(self):
        backend = TrustModelBackend()
        self.assertEqual(backend.get_group_permissions(self.alice, {}), set())
        self.assertEqual(backend.get_all_permissions(self.alice, {}), set())
        self.assertFalse(backend.has_perm(self.alice, 'auth.change_user', self.alice))
        self.assertFalse(
            kernel_config().configured_backend().registry.plan_for(
                User,
            ).records
        )
        self.assertFalse(hasattr(Content, '_contents'))
        self.assertFalse(hasattr(TrustModelBackend, '_get_trusts'))
