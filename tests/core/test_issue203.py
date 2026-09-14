"""#203 / #189 B5: public add_named_filter reject boundaries.

Public ``BackendHandle.add_named_filter`` registration, mixin
``has_perm``, and fixed-query bounds only. Does not assert private
``_ir`` helpers, dunder/repr/hash/cache shapes, or read/mutate
registry/compiler storage to prove cleanup.

Decimal, UUID, date, time, datetime, timedelta, and ``bytes`` compare
successfully against a matching field type. Those families are omitted
from the reject matrix and recorded as accepted public grammar. They
still fail closed when compared to an incompatible field.
"""

from contextlib import contextmanager
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import CharField, ExpressionWrapper, F, Value
from django.db.models.functions import Concat
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps
from django.utils.functional import SimpleLazyObject
from django.utils.translation import gettext_lazy

from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.conditions import PermissionConditionError
from trusts.core import BackendHandle, PlanQueryCompiler, TrustsRegistry


PERM = 'trusts_tests.change_note'
OPEN = '%s:open' % PERM


class _BoundBackend(TrustModelBackendMixin, ModelBackend):
    """Mixin backend bound to one isolated handle for public has_perm."""

    def __init__(self, handle):
        super().__init__()
        self._bound_handle = handle

    def _own_handle(self):
        return self._bound_handle


class _BuilderLog(object):
    def __init__(self, impl):
        self.impl = impl
        self.calls = []

    def __call__(self, u, p, o):
        self.calls.append((u, p, o))
        return self.impl(u, p, o)


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


def _note_models():
    User = get_user_model()

    class Tag(models.Model):
        name = models.CharField(max_length=20)

        class Meta:
            app_label = 'trusts_tests'

    class Note(models.Model):
        title = models.CharField(max_length=40)
        confidential = models.BooleanField(default=False)
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        amount = models.DecimalField(max_digits=8, decimal_places=2, null=True)
        token = models.UUIDField(null=True)
        published = models.DateField(null=True)
        opens = models.TimeField(null=True)
        published_at = models.DateTimeField(null=True)
        duration = models.DurationField(null=True)
        blob = models.BinaryField(null=True)
        tags = models.ManyToManyField(Tag)

        class Meta:
            app_label = 'trusts_tests'

    class NoteGrant(models.Model):
        note = models.ForeignKey(
            Note, on_delete=models.CASCADE, related_name='grants',
        )
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Tag, Note, NoteGrant


def _handle(note_grant):
    handle = BackendHandle(
        path='tests.core.issue203',
        registry=TrustsRegistry(),
        compiler=PlanQueryCompiler(),
    )
    handle.register_relationship(
        note_grant,
        user='user',
        permission='permission',
        content='note',
    )
    return handle


def _permission(model):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='change_note',
        defaults={'name': 'Can change note'},
    )
    return permission


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterRejectBoundaryTest(TransactionTestCase):
    def setUp(self):
        self.Tag, self.Note, self.NoteGrant = _note_models()
        self.handle = _handle(self.NoteGrant)
        self.backend = _BoundBackend(self.handle)

    def _reject(self, code, builder, needle):
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionError) as ctx:
                self.handle.add_named_filter(self.Note, code, builder)
        self.assertIn(needle, str(ctx.exception))

    def _cannot_authorize(self, *codes):
        User = get_user_model()
        with _tables(self.Tag, self.Note, self.NoteGrant):
            alice = User.objects.create_user('alice-203r', password='x')
            change = _permission(self.Note)
            note = self.Note.objects.create(title='open', owner=alice)
            self.NoteGrant.objects.create(
                note=note, user=alice, permission=change,
            )
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, PERM, note))
            for code in codes:
                filtered = '%s:%s' % (PERM, code)
                with self.assertNumQueries(0):
                    self.assertFalse(
                        self.backend.has_perm(alice, filtered, note),
                    )

    def test_unsupported_value_families_reject_at_register_with_zero_sql(self):
        uid = uuid4()
        cases = (
            (
                'manager',
                lambda u, p, o: o.owner == self.Note.objects,
                'Manager',
            ),
            (
                'promise',
                lambda u, p, o: o.title == gettext_lazy('x'),
                'promise',
            ),
            (
                'simple_lazy',
                lambda u, p, o: o.title == SimpleLazyObject(lambda: 'x'),
                'Lazy',
            ),
            (
                'f_expr',
                lambda u, p, o: o.title == F('title'),
                'F',
            ),
            (
                'value_expr',
                lambda u, p, o: o.title == Value('x'),
                'Value',
            ),
            (
                'expr_wrap',
                lambda u, p, o: o.title == ExpressionWrapper(
                    F('title'), output_field=CharField(),
                ),
                'ExpressionWrapper',
            ),
            (
                'concat',
                lambda u, p, o: o.title == Concat(F('title'), Value('x')),
                'Concat',
            ),
            (
                'decimal_title',
                lambda u, p, o: o.title == Decimal('1.5'),
                'Decimal',
            ),
            (
                'uuid_title',
                lambda u, p, o: o.title == uid,
                'UUID',
            ),
            (
                'date_title',
                lambda u, p, o: o.title == date(2026, 1, 1),
                'date',
            ),
            (
                'time_title',
                lambda u, p, o: o.title == time(12, 0),
                'time',
            ),
            (
                'datetime_title',
                lambda u, p, o: o.title == datetime(2026, 1, 1),
                'datetime',
            ),
            (
                'timedelta_title',
                lambda u, p, o: o.title == timedelta(days=1),
                'timedelta',
            ),
            (
                'bytes_title',
                lambda u, p, o: o.title == b'x',
                'bytes',
            ),
            (
                'bytearray_blob',
                lambda u, p, o: o.blob == bytearray(b'x'),
                'bytearray',
            ),
            (
                'memoryview_blob',
                lambda u, p, o: o.blob == memoryview(b'x'),
                'memoryview',
            ),
        )
        for code, builder, needle in cases:
            self._reject(code, builder, needle)
        self._cannot_authorize(*(code for code, _builder, _needle in cases))

    def test_unsupported_relationship_paths_reject_at_register_with_zero_sql(self):
        cases = (
            (
                'm2m_tags',
                lambda u, p, o: o.tags != None,
                'tags',
            ),
            (
                'rev_o2m',
                lambda u, p, o: o.grants != None,
                'grants',
            ),
            (
                'm2m_groups',
                lambda u, p, o: u.groups != None,
                'groups',
            ),
            (
                'perm_hop',
                lambda u, p, o: p.codename == 'change_note',
                'Permission references',
            ),
            (
                'title_hop',
                lambda u, p, o: o.title.foo == 'x',
                'Cannot traverse',
            ),
        )
        for code, builder, needle in cases:
            self._reject(code, builder, needle)
        self._cannot_authorize(*(code for code, _builder, _needle in cases))

    def test_failed_builder_does_not_replace_valid_or_create_a_grant(self):
        User = get_user_model()
        log = _BuilderLog(lambda u, p, o: o.confidential != True)
        with self.assertNumQueries(0):
            self.handle.add_named_filter(self.Note, 'open', log)
        self.assertEqual(len(log.calls), 1)

        with _tables(self.Tag, self.Note, self.NoteGrant):
            alice = User.objects.create_user('alice-203p', password='x')
            bob = User.objects.create_user('bob-203p', password='x')
            change = _permission(self.Note)
            opened = self.Note.objects.create(title='open', owner=alice)
            secret = self.Note.objects.create(
                title='secret', owner=alice, confidential=True,
            )
            for note in (opened, secret):
                self.NoteGrant.objects.create(
                    note=note, user=alice, permission=change,
                )

            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, OPEN, opened))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(alice, OPEN, secret))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(bob, OPEN, opened))
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, PERM, secret))

            with self.assertNumQueries(0):
                with self.assertRaises(PermissionConditionError):
                    self.handle.add_named_filter(
                        self.Note,
                        'open',
                        lambda u, p, o: o.title == Decimal('1.5'),
                    )
                with self.assertRaises(PermissionConditionError):
                    self.handle.add_named_filter(
                        self.Note,
                        'partial_203',
                        lambda u, p, o: o.owner == self.Note.objects,
                    )

            self.assertEqual(len(log.calls), 1)
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, OPEN, opened))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(alice, OPEN, secret))
            with self.assertNumQueries(0):
                self.assertFalse(
                    self.backend.has_perm(
                        alice, '%s:partial_203' % PERM, opened,
                    ),
                )
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(bob, PERM, opened))

    def test_supported_surface_stays_builder_once_and_count_independent(self):
        User = get_user_model()
        log = _BuilderLog(
            lambda u, p, o: (u == o.owner) & (o.confidential != True),
        )
        with self.assertNumQueries(0):
            self.handle.add_named_filter(self.Note, 'open', log)
            self.handle.add_named_filter(
                self.Note, 'titled', lambda u, p, o: o.title != 'secret',
            )
            self.handle.add_named_filter(
                self.Note, 'owned', lambda u, p, o: u == o.owner,
            )
            self.handle.add_named_filter(
                self.Note,
                'amount_ok',
                lambda u, p, o: o.amount == Decimal('1.50'),
            )
            self.handle.add_named_filter(
                self.Note, 'token_ok', lambda u, p, o: o.token == uuid4(),
            )
            self.handle.add_named_filter(
                self.Note,
                'date_ok',
                lambda u, p, o: o.published == date(2026, 1, 1),
            )
            self.handle.add_named_filter(
                self.Note, 'time_ok', lambda u, p, o: o.opens == time(12, 0),
            )
            self.handle.add_named_filter(
                self.Note,
                'datetime_ok',
                lambda u, p, o: o.published_at == datetime(2026, 1, 1),
            )
            self.handle.add_named_filter(
                self.Note,
                'duration_ok',
                lambda u, p, o: o.duration == timedelta(days=1),
            )
            self.handle.add_named_filter(
                self.Note, 'blob_ok', lambda u, p, o: o.blob == b'x',
            )
        self.assertEqual(len(log.calls), 1)

        with _tables(self.Tag, self.Note, self.NoteGrant):
            alice = User.objects.create_user('alice-203s', password='x')
            bob = User.objects.create_user('bob-203s', password='x')
            change = _permission(self.Note)
            first = self.Note.objects.create(title='one', owner=alice)
            second = self.Note.objects.create(title='two', owner=alice)
            secret = self.Note.objects.create(
                title='secret', owner=alice, confidential=True,
            )
            for note in (first, second, secret):
                self.NoteGrant.objects.create(
                    note=note, user=alice, permission=change,
                )
            one = self.Note.objects.filter(pk=first.pk)
            many = self.Note.objects.filter(pk__in=[first.pk, second.pk])
            mixed = self.Note.objects.filter(
                pk__in=[first.pk, second.pk, secret.pk],
            )

            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, OPEN, first))
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, OPEN, one))
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, OPEN, many))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(alice, OPEN, mixed))
            with self.assertNumQueries(1):
                self.assertTrue(self.backend.has_perm(alice, PERM, mixed))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(alice, OPEN, secret))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(bob, OPEN, first))
            with self.assertNumQueries(1):
                self.assertFalse(self.backend.has_perm(bob, PERM, first))
            with self.assertNumQueries(1):
                self.assertTrue(
                    self.backend.has_perm(
                        alice, '%s:titled' % PERM, first,
                    ),
                )
            with self.assertNumQueries(1):
                self.assertTrue(
                    self.backend.has_perm(
                        alice, '%s:owned' % PERM, first,
                    ),
                )
            self.assertEqual(len(log.calls), 1)


class Issue203SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue203', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue203', PAIR_KERNEL_SUITE)
