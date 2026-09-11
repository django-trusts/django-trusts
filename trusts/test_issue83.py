"""S5: bounded Ref dependent-content grammar (issue #83).

Isolated generic mock models only. No production historical nouns, no
Group/Junction contribution, and no deletion of legacy registry
machinery. Structural and behavioral tests only — no source-token or
``inspect.getsource`` assertions.
"""

import types
from contextlib import contextmanager

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
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    common_permissions,
)


def _j1_models():
    """FolderGrant → Folder ← Row → Payload (J1: F + rev O2M + forward)."""

    class Folder(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Payload(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Row(models.Model):
        folder = models.ForeignKey(
            Folder, related_name='rows', on_delete=models.CASCADE,
        )
        content = models.ForeignKey(
            Payload, related_name='rows', on_delete=models.CASCADE,
        )
        alt_content = models.ForeignKey(
            Payload, related_name='alt_rows', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    User = get_user_model()

    class FolderGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class FolderGroupGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Folder, Payload, Row, FolderGrant, FolderGroupGrant


def _holder_chain(image_kind, meta_kind=None):
    """HolderGrant → Holder ← Item, then documented image / meta encodings.

    ``image_kind`` / ``meta_kind`` are ``'o2m'``, ``'o2o'``, or ``'forward'``.
    """

    class Holder(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Owner(models.Model):
        name = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    class Tag(models.Model):
        name = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    if image_kind == 'forward':
        class ImageMeta(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class Image(models.Model):
            title = models.CharField(max_length=40)
            image = models.ForeignKey(
                ImageMeta, related_name='parents', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Item(models.Model):
            holder = models.ForeignKey(
                Holder, related_name='items', on_delete=models.CASCADE,
            )
            image = models.ForeignKey(
                Image, related_name='items', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
    else:
        class Item(models.Model):
            holder = models.ForeignKey(
                Holder, related_name='items', on_delete=models.CASCADE,
            )
            owner = models.ForeignKey(
                Owner, related_name='items', on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField(Tag)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        if image_kind == 'o2o':
            class Image(models.Model):
                item = models.OneToOneField(
                    Item, related_name='image', on_delete=models.CASCADE,
                )
                title = models.CharField(max_length=40)

                class Meta:
                    app_label = 'trusts_tests'
        else:
            class Image(models.Model):
                item = models.ForeignKey(
                    Item, related_name='image', on_delete=models.CASCADE,
                )
                title = models.CharField(max_length=40)

                class Meta:
                    app_label = 'trusts_tests'

        if meta_kind == 'o2o':
            class ImageMeta(models.Model):
                image = models.OneToOneField(
                    Image, related_name='image', on_delete=models.CASCADE,
                )
                title = models.CharField(max_length=40)

                class Meta:
                    app_label = 'trusts_tests'
        elif meta_kind == 'o2m':
            class ImageMeta(models.Model):
                image = models.ForeignKey(
                    Image, related_name='image', on_delete=models.CASCADE,
                )
                title = models.CharField(max_length=40)

                class Meta:
                    app_label = 'trusts_tests'
        else:
            class ImageMeta(models.Model):
                title = models.CharField(max_length=40)

                class Meta:
                    app_label = 'trusts_tests'

    class ExtraHop(models.Model):
        meta = models.ForeignKey(
            ImageMeta, related_name='extra', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Profile(models.Model):
        holder = models.OneToOneField(
            Holder, related_name='profile', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    User = get_user_model()

    class HolderGrant(models.Model):
        holder = models.ForeignKey(Holder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        content_type = models.ForeignKey(
            ContentType, on_delete=models.CASCADE,
        )
        object_id = models.PositiveIntegerField()
        target = GenericForeignKey('content_type', 'object_id')

        class Meta:
            app_label = 'trusts_tests'

    class Wrapper(models.Model):
        holder = models.ForeignKey(Holder, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class WrapperGrant(models.Model):
        wrapper = models.ForeignKey(Wrapper, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return (
        Holder, Owner, Tag, Item, Image, ImageMeta, ExtraHop, Profile,
        HolderGrant, Wrapper, WrapperGrant,
    )


def _d1_models():
    return _holder_chain('o2m')


def _d1o_models():
    return _holder_chain('o2o')


def _d2_models():
    return _holder_chain('o2m', 'o2m')


def _d2o_models():
    return _holder_chain('o2o', 'o2o')


def _d2f_models():
    return _holder_chain('forward', 'forward')


def _composite_models():
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

    return Pair, PairGrant


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
        app_label='trusts_tests', model='payload',
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _pks(rows):
    return {row.pk for row in rows}


class _SplitCompiler(object):
    """Direct plan OR group-registry plan. Group-only uses the group plan."""

    historical_fallback = False

    def __init__(self, group_registry):
        self.group_registry = group_registry

    def complete_exists(self, plan, candidates, user, permission):
        parts = []
        if plan.records:
            direct = plan.content_exists(user, permission)
            if direct is not None:
                parts.append(direct)
        group = self.group_exists(plan, candidates, user, permission)
        if group is not None:
            parts.append(group)
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return Q(parts[0]) | Q(parts[1])

    def group_exists(self, plan, candidates, user, permission):
        if isinstance(permission, models.Model):
            group_plan = self.group_registry.plan_for(
                candidates, user=user, permission=permission,
            )
        else:
            group_plan = self.group_registry.plan_for(candidates, user=user)
        if not group_plan.records:
            return None
        return group_plan.content_exists(user, permission)


def _direct_handle(registry, path='tests.s5.direct'):
    return BackendHandle(
        path=path, registry=registry, compiler=PlanQueryCompiler(),
    )


def _assert_record(test, record, *, root, path, model, lookup, target=None):
    test.assertIs(record.root, root)
    test.assertEqual(record.content_path, path)
    test.assertIs(record.content_model, model)
    test.assertEqual(record.content_field, lookup)
    if target is None:
        target = model._meta.pk.attname
    test.assertEqual(record.content_target, target)


def _assert_no_historical_names(*models_):
    forbidden = {'Trust', 'Content', 'Junction', 'Receipt', 'Group', 'Role'}
    for model in models_:
        names = {cls.__name__ for cls in model.__mro__}
        leftover = forbidden.intersection(names)
        if leftover:
            raise AssertionError('historical noun in mock MRO: %s' % leftover)
        if model.__module__ != __name__:
            raise AssertionError(
                'mock %s is not isolated (%s)' % (model.__name__, model.__module__)
            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryDependentGrammarRegistrationTest(SimpleTestCase):
    def test_j1_registers_forward_reverse_forward(self):
        Folder, Payload, Row, FolderGrant, _group = _j1_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        record = registry.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        _assert_record(
            self, record, root=FolderGrant,
            path=('folder', 'rows', 'content'),
            model=Payload, lookup='folder__rows__content',
        )
        self.assertEqual(registry.plan_for(Payload).records, (record,))
        self.assertEqual(registry.records, (record,))
        _assert_no_historical_names(Folder, Payload, Row, FolderGrant)

    def test_d1_registers_gateway_plus_reverse_o2m_suffix(self):
        Holder, _owner, _tag, Item, Image, _meta, _extra, _profile, Grant, _w, _wg = (
            _d1_models()
        )
        registry = TrustsRegistry()
        j = Ref(Grant)
        item_rec = registry.register(
            content=j.holder.items, user=j.user, permission=j.permission,
        )
        image_rec = registry.register(
            content=j.holder.items.image, user=j.user, permission=j.permission,
        )
        _assert_record(
            self, item_rec, root=Grant, path=('holder', 'items'),
            model=Item, lookup='holder__items',
        )
        _assert_record(
            self, image_rec, root=Grant, path=('holder', 'items', 'image'),
            model=Image, lookup='holder__items__image',
        )
        self.assertEqual(registry.records_for_root(Grant), (item_rec, image_rec))

    def test_d1o_registers_gateway_plus_reverse_o2o_suffix(self):
        _holder, _owner, _tag, _item, Image, _meta, _extra, _profile, Grant, _w, _wg = (
            _d1o_models()
        )
        registry = TrustsRegistry()
        j = Ref(Grant)
        record = registry.register(
            content=j.holder.items.image, user=j.user, permission=j.permission,
        )
        _assert_record(
            self, record, root=Grant, path=('holder', 'items', 'image'),
            model=Image, lookup='holder__items__image',
        )

    def _assert_both_dependent_depths(self, factory):
        (
            _holder, _owner, _tag, _item, Image, ImageMeta,
            _extra, _profile, Grant, _w, _wg,
        ) = factory()
        registry = TrustsRegistry()
        j = Ref(Grant)
        depth1 = registry.register(
            content=j.holder.items.image,
            user=j.user,
            permission=j.permission,
        )
        depth2 = registry.register(
            content=j.holder.items.image.image,
            user=j.user,
            permission=j.permission,
        )
        _assert_record(
            self, depth1, root=Grant,
            path=('holder', 'items', 'image'),
            model=Image, lookup='holder__items__image',
        )
        _assert_record(
            self, depth2, root=Grant,
            path=('holder', 'items', 'image', 'image'),
            model=ImageMeta, lookup='holder__items__image__image',
        )
        self.assertEqual(registry.plan_for(Image).records, (depth1,))
        self.assertEqual(registry.plan_for(ImageMeta).records, (depth2,))

    def test_d2_registers_both_documented_depths(self):
        self._assert_both_dependent_depths(_d2_models)

    def test_d2o_registers_both_documented_depths(self):
        self._assert_both_dependent_depths(_d2o_models)

    def test_d2f_registers_both_documented_depths(self):
        self._assert_both_dependent_depths(_d2f_models)

    def test_two_forward_hops_then_gateway_remain_expressible(self):
        Holder, _owner, _tag, Item, _image, _meta, _extra, _profile, _g, Wrapper, WrapperGrant = (
            _d1_models()
        )
        registry = TrustsRegistry()
        j = Ref(WrapperGrant)
        record = registry.register(
            content=j.wrapper.holder.items,
            user=j.user,
            permission=j.permission,
        )
        _assert_record(
            self, record, root=WrapperGrant,
            path=('wrapper', 'holder', 'items'),
            model=Item, lookup='wrapper__holder__items',
        )

    def test_direct_and_trailing_reverse_still_register(self):
        Folder, Payload, Row, FolderGrant, _group = _j1_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        folder_rec = registry.register(
            content=j.folder, user=j.user, permission=j.permission,
        )
        row_rec = registry.register(
            content=j.folder.rows, user=j.user, permission=j.permission,
        )
        _assert_record(
            self, folder_rec, root=FolderGrant, path=('folder',),
            model=Folder, lookup='folder',
        )
        _assert_record(
            self, row_rec, root=FolderGrant, path=('folder', 'rows'),
            model=Row, lookup='folder__rows',
        )

    def test_rejections_are_deterministic_and_leave_records_unchanged(self):
        (
            Holder, _owner, _tag, _item, _image, _meta, _extra, _profile,
            Grant, Wrapper, WrapperGrant,
        ) = _d2_models()
        _pair, PairGrant = _composite_models()
        registry = TrustsRegistry()
        j = Ref(Grant)
        first = registry.register(
            content=j.holder.items.image,
            user=j.user,
            permission=j.permission,
        )
        stored = registry.records
        wrapper = Ref(WrapperGrant)
        pair = Ref(PairGrant)

        class GrantNote(models.Model):
            grant = models.ForeignKey(
                Grant, related_name='notes', on_delete=models.CASCADE,
            )
            holder = models.ForeignKey(Holder, on_delete=models.CASCADE)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        with self.assertRaisesRegex(TrustsConfigurationError, r'reverse'):
            registry.register(
                content=j.notes,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'before the gateway'):
            registry.register(
                content=j.notes.holder,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'reverse one-to-one'):
            registry.register(
                content=j.holder.profile,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'multi-valued'):
            registry.register(
                content=j.holder.items.tags,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'generic foreign key'):
            registry.register(
                content=j.target,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'more than two hops'):
            registry.register(
                content=j.holder.items.image.image.extra,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'forward path ending'):
            registry.register(
                content=wrapper.wrapper.holder,
                user=wrapper.user,
                permission=wrapper.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'composite|target fields'):
            registry.register(
                content=pair.pair, user=pair.user, permission=pair.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct|reverse'):
            registry.register(
                content=j.holder,
                user=j.holder.items,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'missing field'):
            registry.register(
                content=j.holder.item_set,
                user=j.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'same root'):
            registry.register(
                content=j.holder.items,
                user=wrapper.user,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Duplicate'):
            registry.register(
                content=j.holder.items.image,
                user=j.user,
                permission=j.permission,
            )
        self.assertEqual(registry.records, stored)
        self.assertEqual(registry.records, (first,))
        self.assertIs(registry.records[0], first)

    def test_same_root_same_terminal_via_alt_suffix_is_conflict(self):
        Folder, Payload, _row, FolderGrant, _group = _j1_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        first = registry.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        with self.assertRaisesRegex(TrustsConfigurationError, r'Conflicting'):
            registry.register(
                content=j.folder.rows.alt_content,
                user=j.user,
                permission=j.permission,
            )
        self.assertEqual(registry.records, (first,))
        self.assertEqual(first.content_path, ('folder', 'rows', 'content'))

    def test_user_and_permission_remain_direct(self):
        _folder, _payload, _row, FolderGrant, _group = _j1_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct|reverse'):
            registry.register(
                content=j.folder,
                user=j.folder.rows,
                permission=j.permission,
            )
        with self.assertRaisesRegex(TrustsConfigurationError, r'direct|reverse'):
            registry.register(
                content=j.folder,
                user=j.user,
                permission=j.folder.rows.content,
            )
        self.assertEqual(registry.records, ())

    def test_registration_executes_zero_queries(self):
        _folder, _payload, _row, FolderGrant, _group = _j1_models()
        registry = TrustsRegistry()
        j = Ref(FolderGrant)
        registry.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                content=j.folder.rows.content,
                user=j.user,
                permission=j.permission,
            )

    def test_core_module_has_no_historical_import_or_global(self):
        import trusts.core as core

        forbidden = {
            'Trust',
            'Content',
            'Junction',
            'Receipt',
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


class _TerminalProjectionMixin(object):
    """Shared object / queryset / enumeration / all-match assertions."""

    def _users(self, suffix):
        User = get_user_model()
        self.alice = User.objects.create_user(
            username='alice-%s' % suffix, password='x',
        )
        self.bob = User.objects.create_user(
            username='bob-%s' % suffix, password='x',
        )
        self.read = _perm('read_%s' % suffix)
        self.write = _perm('write_%s' % suffix)

    def _assert_terminal(self, registry, Model, granted, sibling, other):
        handle = _direct_handle(registry)
        self.assertTrue(
            registry.has_permission(self.alice, granted, self.read),
        )
        self.assertTrue(
            registry.has_permission(self.alice, sibling, self.read),
        )
        self.assertFalse(
            registry.has_permission(self.alice, granted, self.write),
        )
        self.assertFalse(
            registry.has_permission(self.bob, granted, self.read),
        )
        self.assertFalse(
            registry.has_permission(self.alice, other, self.read),
        )
        self.assertEqual(
            _pks(registry.permissions_for(self.alice, granted)),
            {self.read.pk},
        )
        self.assertEqual(
            list(registry.permissions_for(self.alice, other)),
            [],
        )
        expected = [granted, sibling]
        qs = registry.filter_authorized(
            Model.objects.order_by('pk'), self.alice, self.read,
        )
        self.assertIsInstance(qs, QuerySet)
        with self.assertNumQueries(1):
            self.assertEqual(list(qs), expected)

        granted_qs = Model.objects.filter(pk__in=[granted.pk, sibling.pk])
        mixed_qs = Model.objects.order_by('pk')
        with self.assertNumQueries(1):
            self.assertTrue(all_match((handle,), granted, self.alice, self.read))
        with self.assertNumQueries(1):
            self.assertTrue(
                all_match((handle,), granted_qs, self.alice, self.read),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                all_match((handle,), mixed_qs, self.alice, self.read),
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(common_permissions((handle,), granted, self.alice)),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(common_permissions((handle,), granted_qs, self.alice)),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(common_permissions((handle,), mixed_qs, self.alice)),
                [],
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(common_permissions(
                    (handle,), granted_qs, self.alice, kind='group',
                )),
                [],
            )
        plan = registry.plan_for(granted, user=self.alice, permission=self.read)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(plan.common_permissions(self.alice, granted)), {self.read.pk})
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(plan.common_permissions(self.alice, granted_qs)),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(plan.common_permissions(self.alice, mixed_qs)),
                [],
            )

    def _assert_shared_row(self, registry, granted, other_scope):
        self.assertFalse(
            registry.has_permission(self.alice, granted, self.write),
        )
        self.assertFalse(
            registry.has_permission(self.alice, other_scope, self.read),
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryJ1ProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        (
            self.Folder, self.Payload, self.Row,
            self.FolderGrant, self.FolderGroupGrant,
        ) = _j1_models()
        self._table_cm = _tables(
            self.Folder, self.Payload, self.Row,
            self.FolderGrant, self.FolderGroupGrant,
        )
        self._table_cm.__enter__()
        self._users('j1')
        self.folder_a = self.Folder.objects.create(title='A')
        self.folder_b = self.Folder.objects.create(title='B')
        self.pay_a1 = self.Payload.objects.create(title='A1')
        self.pay_a2 = self.Payload.objects.create(title='A2')
        self.pay_b1 = self.Payload.objects.create(title='B1')
        self.Row.objects.create(
            folder=self.folder_a, content=self.pay_a1, alt_content=self.pay_b1,
        )
        self.Row.objects.create(
            folder=self.folder_a, content=self.pay_a2, alt_content=self.pay_b1,
        )
        self.Row.objects.create(
            folder=self.folder_b, content=self.pay_b1, alt_content=self.pay_a1,
        )
        extras = [
            self.Payload.objects.create(title='X%s' % i) for i in range(6)
        ]
        for payload in extras:
            self.Row.objects.create(
                folder=self.folder_b, content=payload, alt_content=self.pay_a1,
            )
        self.registry = TrustsRegistry()
        j = Ref(self.FolderGrant)
        self.registry.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_b, user=self.alice, permission=self.write,
        )
        self.FolderGrant.objects.create(
            folder=self.folder_b, user=self.bob, permission=self.read,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_j1_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.Payload,
            self.pay_a1, self.pay_a2, self.pay_b1,
        )
        self._assert_shared_row(self.registry, self.pay_a1, self.pay_b1)
        self.assertTrue(
            self.registry.has_permission(self.bob, self.pay_b1, self.read),
        )
        self.assertTrue(
            self.registry.has_permission(self.alice, self.pay_b1, self.write),
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryD1ProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        (
            self.Holder, _owner, _tag, self.Item, self.Image, _meta,
            _extra, _profile, self.Grant, _w, _wg,
        ) = _d1_models()
        owner = _owner
        self._table_cm = _tables(
            self.Holder, owner, _tag, self.Item, self.Image, self.Grant,
        )
        self._table_cm.__enter__()
        self._users('d1')
        self.owner = owner.objects.create(name='o')
        self.h_a = self.Holder.objects.create(title='A')
        self.h_b = self.Holder.objects.create(title='B')
        self.item_a1 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A1',
        )
        self.item_a2 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A2',
        )
        self.item_b1 = self.Item.objects.create(
            holder=self.h_b, owner=self.owner, title='B1',
        )
        self.img_a1 = self.Image.objects.create(item=self.item_a1, title='A1')
        self.img_a2 = self.Image.objects.create(item=self.item_a2, title='A2')
        self.img_b1 = self.Image.objects.create(item=self.item_b1, title='B1')
        for i in range(6):
            item = self.Item.objects.create(
                holder=self.h_b, owner=self.owner, title='X%s' % i,
            )
            self.Image.objects.create(item=item, title='X%s' % i)
        self.registry = TrustsRegistry()
        j = Ref(self.Grant)
        self.registry.register(
            content=j.holder.items.image, user=j.user, permission=j.permission,
        )
        self.Grant.objects.create(
            holder=self.h_a, user=self.alice, permission=self.read,
            content_type=ContentType.objects.get_for_model(self.Holder),
            object_id=self.h_a.pk,
        )
        self.Grant.objects.create(
            holder=self.h_b, user=self.alice, permission=self.write,
            content_type=ContentType.objects.get_for_model(self.Holder),
            object_id=self.h_b.pk,
        )
        self.Grant.objects.create(
            holder=self.h_b, user=self.bob, permission=self.read,
            content_type=ContentType.objects.get_for_model(self.Holder),
            object_id=self.h_b.pk,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_d1_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.Image,
            self.img_a1, self.img_a2, self.img_b1,
        )
        self._assert_shared_row(self.registry, self.img_a1, self.img_b1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryD1oProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        (
            self.Holder, owner, _tag, self.Item, self.Image, _meta,
            _extra, _profile, self.Grant, _w, _wg,
        ) = _d1o_models()
        self._table_cm = _tables(
            self.Holder, owner, _tag, self.Item, self.Image, self.Grant,
        )
        self._table_cm.__enter__()
        self._users('d1o')
        self.owner = owner.objects.create(name='o')
        self.h_a = self.Holder.objects.create(title='A')
        self.h_b = self.Holder.objects.create(title='B')
        self.item_a1 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A1',
        )
        self.item_a2 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A2',
        )
        self.item_b1 = self.Item.objects.create(
            holder=self.h_b, owner=self.owner, title='B1',
        )
        self.img_a1 = self.Image.objects.create(item=self.item_a1, title='A1')
        self.img_a2 = self.Image.objects.create(item=self.item_a2, title='A2')
        self.img_b1 = self.Image.objects.create(item=self.item_b1, title='B1')
        self.registry = TrustsRegistry()
        j = Ref(self.Grant)
        self.registry.register(
            content=j.holder.items.image, user=j.user, permission=j.permission,
        )
        self.Grant.objects.create(
            holder=self.h_a, user=self.alice, permission=self.read,
            content_type=ContentType.objects.get_for_model(self.Holder),
            object_id=self.h_a.pk,
        )
        self.Grant.objects.create(
            holder=self.h_b, user=self.alice, permission=self.write,
            content_type=ContentType.objects.get_for_model(self.Holder),
            object_id=self.h_b.pk,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_d1o_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.Image,
            self.img_a1, self.img_a2, self.img_b1,
        )
        self._assert_shared_row(self.registry, self.img_a1, self.img_b1)


def _seed_depth2(self, factory, suffix, reverse_meta=True):
    models_ = factory()
    (
        self.Holder, owner, tag, self.Item, self.Image, self.ImageMeta,
        extra, profile, self.Grant, _w, _wg,
    ) = models_
    table_models = [
        self.Holder, owner, tag, self.Item, self.Image, self.ImageMeta,
        self.Grant,
    ]
    self._table_cm = _tables(*table_models)
    self._table_cm.__enter__()
    self._users(suffix)
    self.h_a = self.Holder.objects.create(title='A')
    self.h_b = self.Holder.objects.create(title='B')
    if reverse_meta:
        self.owner = owner.objects.create(name='o')
        self.item_a1 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A1',
        )
        self.item_a2 = self.Item.objects.create(
            holder=self.h_a, owner=self.owner, title='A2',
        )
        self.item_b1 = self.Item.objects.create(
            holder=self.h_b, owner=self.owner, title='B1',
        )
        self.img_a1 = self.Image.objects.create(item=self.item_a1, title='A1')
        self.img_a2 = self.Image.objects.create(item=self.item_a2, title='A2')
        self.img_b1 = self.Image.objects.create(item=self.item_b1, title='B1')
        self.meta_a1 = self.ImageMeta.objects.create(image=self.img_a1, title='A1')
        self.meta_a2 = self.ImageMeta.objects.create(image=self.img_a2, title='A2')
        self.meta_b1 = self.ImageMeta.objects.create(image=self.img_b1, title='B1')
        for i in range(5):
            item = self.Item.objects.create(
                holder=self.h_b, owner=self.owner, title='X%s' % i,
            )
            image = self.Image.objects.create(item=item, title='X%s' % i)
            self.ImageMeta.objects.create(image=image, title='X%s' % i)
    else:
        self.meta_a1 = self.ImageMeta.objects.create(title='A1')
        self.meta_a2 = self.ImageMeta.objects.create(title='A2')
        self.meta_b1 = self.ImageMeta.objects.create(title='B1')
        self.img_a1 = self.Image.objects.create(title='A1', image=self.meta_a1)
        self.img_a2 = self.Image.objects.create(title='A2', image=self.meta_a2)
        self.img_b1 = self.Image.objects.create(title='B1', image=self.meta_b1)
        self.item_a1 = self.Item.objects.create(holder=self.h_a, image=self.img_a1)
        self.item_a2 = self.Item.objects.create(holder=self.h_a, image=self.img_a2)
        self.item_b1 = self.Item.objects.create(holder=self.h_b, image=self.img_b1)
        for i in range(5):
            meta = self.ImageMeta.objects.create(title='X%s' % i)
            image = self.Image.objects.create(title='X%s' % i, image=meta)
            self.Item.objects.create(holder=self.h_b, image=image)
    self.registry = TrustsRegistry()
    j = Ref(self.Grant)
    self.registry.register(
        content=j.holder.items.image.image,
        user=j.user,
        permission=j.permission,
    )
    extra_kwargs = {}
    if 'content_type' in {f.name for f in self.Grant._meta.fields}:
        extra_kwargs = {
            'content_type': ContentType.objects.get_for_model(self.Holder),
        }
    self.Grant.objects.create(
        holder=self.h_a, user=self.alice, permission=self.read,
        object_id=self.h_a.pk, **extra_kwargs,
    )
    self.Grant.objects.create(
        holder=self.h_b, user=self.alice, permission=self.write,
        object_id=self.h_b.pk, **extra_kwargs,
    )
    self.Grant.objects.create(
        holder=self.h_b, user=self.bob, permission=self.read,
        object_id=self.h_b.pk, **extra_kwargs,
    )
    return extra, profile


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryD2ProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        _seed_depth2(self, _d2_models, 'd2', reverse_meta=True)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_d2_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.ImageMeta,
            self.meta_a1, self.meta_a2, self.meta_b1,
        )
        self._assert_shared_row(self.registry, self.meta_a1, self.meta_b1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryD2oProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        _seed_depth2(self, _d2o_models, 'd2o', reverse_meta=True)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_d2o_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.ImageMeta,
            self.meta_a1, self.meta_a2, self.meta_b1,
        )
        self._assert_shared_row(self.registry, self.meta_a1, self.meta_b1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryD2fProjectionTest(_TerminalProjectionMixin, TransactionTestCase):
    def setUp(self):
        _seed_depth2(self, _d2f_models, 'd2f', reverse_meta=False)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_d2f_projections_agree_and_stay_one_sql(self):
        self._assert_terminal(
            self.registry, self.ImageMeta,
            self.meta_a1, self.meta_a2, self.meta_b1,
        )
        self._assert_shared_row(self.registry, self.meta_a1, self.meta_b1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryDependentGrammarGroupSplitTest(TransactionTestCase):
    def setUp(self):
        (
            self.Folder, self.Payload, self.Row,
            self.FolderGrant, self.FolderGroupGrant,
        ) = _j1_models()
        self._table_cm = _tables(
            self.Folder, self.Payload, self.Row,
            self.FolderGrant, self.FolderGroupGrant,
        )
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user(username='alice-split', password='x')
        self.carol = User.objects.create_user(username='carol-split', password='x')
        self.read = _perm('read_split')
        self.folder_a = self.Folder.objects.create(title='A')
        self.folder_b = self.Folder.objects.create(title='B')
        self.pay_a = self.Payload.objects.create(title='A')
        self.pay_b = self.Payload.objects.create(title='B')
        extras = [self.Payload.objects.create(title='X%s' % i) for i in range(8)]
        self.Row.objects.create(
            folder=self.folder_a, content=self.pay_a, alt_content=self.pay_b,
        )
        self.Row.objects.create(
            folder=self.folder_b, content=self.pay_b, alt_content=self.pay_a,
        )
        for payload in extras:
            self.Row.objects.create(
                folder=self.folder_b, content=payload, alt_content=self.pay_a,
            )
        self.direct = TrustsRegistry()
        j = Ref(self.FolderGrant)
        self.direct.register(
            content=j.folder.rows.content,
            user=j.user,
            permission=j.permission,
        )
        self.group = TrustsRegistry()
        k = Ref(self.FolderGroupGrant)
        self.group.register(
            content=k.folder.rows.content,
            user=k.user,
            permission=k.permission,
        )
        self.handle = BackendHandle(
            path='tests.s5.split',
            registry=self.direct,
            compiler=_SplitCompiler(self.group),
        )
        self.FolderGrant.objects.create(
            folder=self.folder_a, user=self.alice, permission=self.read,
        )
        self.FolderGroupGrant.objects.create(
            folder=self.folder_a, user=self.carol, permission=self.read,
        )

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_direct_versus_group_only_without_per_object_loop(self):
        many = self.Payload.objects.order_by('pk')
        alice_only = self.Payload.objects.filter(pk=self.pay_a.pk)

        with self.assertNumQueries(1):
            self.assertTrue(
                all_match((self.handle,), self.pay_a, self.alice, self.read),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                all_match(
                    (self.handle,), self.pay_a, self.alice, self.read,
                    kind='group',
                ),
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                all_match(
                    (self.handle,), self.pay_a, self.carol, self.read,
                    kind='group',
                ),
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                all_match((self.handle,), self.pay_a, self.carol, self.read),
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                all_match((self.handle,), many, self.alice, self.read),
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(common_permissions((self.handle,), alice_only, self.alice)),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(common_permissions(
                    (self.handle,), alice_only, self.alice, kind='group',
                )),
                [],
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                _pks(common_permissions(
                    (self.handle,), alice_only, self.carol, kind='group',
                )),
                {self.read.pk},
            )
        with self.assertNumQueries(1):
            self.assertEqual(
                list(common_permissions((self.handle,), many, self.alice)),
                [],
            )
        self.assertFalse(
            all_match((self.handle,), self.pay_b, self.alice, self.read),
        )
        self.assertFalse(
            all_match((self.handle,), self.pay_b, self.carol, self.read),
        )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TrustsRegistryDependentGrammarToFieldTest(TransactionTestCase):
    def test_to_field_on_forward_prefix_retains_suffix_correlation(self):
        User = get_user_model()

        class CodedHolder(models.Model):
            code = models.SlugField(unique=True)
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CodedItem(models.Model):
            holder = models.ForeignKey(
                CodedHolder, related_name='items', on_delete=models.CASCADE,
            )
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CodedImage(models.Model):
            item = models.ForeignKey(
                CodedItem, related_name='image', on_delete=models.CASCADE,
            )
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class CodedGrant(models.Model):
            holder = models.ForeignKey(
                CodedHolder, to_field='code', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(CodedHolder, CodedItem, CodedImage, CodedGrant):
            registry = TrustsRegistry()
            j = Ref(CodedGrant)
            record = registry.register(
                content=j.holder.items.image,
                user=j.user,
                permission=j.permission,
            )
            self.assertEqual(record.content_field, 'holder__items__image')
            self.assertEqual(record.content_target, CodedImage._meta.pk.attname)
            self.assertNotEqual(record.content_target, 'code')

            alice = User.objects.create_user(username='alice-tf83', password='x')
            bob = User.objects.create_user(username='bob-tf83', password='x')
            read = _perm('read_coded83')
            write = _perm('write_coded83')
            holder_a = CodedHolder.objects.create(code='alpha', title='A')
            holder_b = CodedHolder.objects.create(code='beta', title='B')
            self.assertNotEqual(holder_a.pk, 'alpha')
            item_a1 = CodedItem.objects.create(holder=holder_a, title='A1')
            item_a2 = CodedItem.objects.create(holder=holder_a, title='A2')
            item_b1 = CodedItem.objects.create(holder=holder_b, title='B1')
            img_a1 = CodedImage.objects.create(item=item_a1, title='A1')
            img_a2 = CodedImage.objects.create(item=item_a2, title='A2')
            img_b1 = CodedImage.objects.create(item=item_b1, title='B1')
            CodedGrant.objects.create(
                holder=holder_a, user=alice, permission=read,
            )

            self.assertTrue(registry.has_permission(alice, img_a1, read))
            self.assertTrue(registry.has_permission(alice, img_a2, read))
            self.assertFalse(registry.has_permission(alice, img_b1, read))
            self.assertFalse(registry.has_permission(bob, img_a1, read))
            self.assertFalse(registry.has_permission(alice, img_a1, write))
            sql = str(registry.filter_authorized(
                CodedImage.objects.order_by('pk'), alice, read,
            ).query).lower()
            self.assertIn('exists', sql)
            self.assertIn('holder', sql)
            with self.assertNumQueries(1):
                self.assertEqual(
                    list(registry.filter_authorized(
                        CodedImage.objects.order_by('pk'), alice, read,
                    )),
                    [img_a1, img_a2],
                )
