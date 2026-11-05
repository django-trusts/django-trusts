"""SQL functions in relation, delegation, and named-filter conditions.

``Now``, ``Lower``, and ``Coalesce`` from ``trusts.functions`` lower at
register time. ``has_perm``, ``.permitted()``, and ``get_permitted_users``
read the same stored tree. Django's own functions are rejected there.
"""
import re
from contextlib import contextmanager
from datetime import date, timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import CharField, F, Value
from django.db.models.functions import Lower as DjangoLower
from django.db.models.functions import Now as DjangoNow
from django.test import TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext, isolate_apps
from django.utils import timezone

from tests.support import compiler, published_class_catalog, render_configured_policy
from trusts.backends import TrustModelBackendMixin
from trusts.errors import PermissionConditionError
from trusts.functions import Coalesce, Lower, Now
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from trusts.plan.grammar import Symbol, walk

PERM = 'trusts_tests.change_sheet'
BACKEND = 'tests.core.test_sql_functions._SqlBackend'


class _SqlBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _clock_token():
    if connection.vendor == 'postgresql':
        return 'STATEMENT_TIMESTAMP'
    if connection.vendor == 'mysql':
        return 'CURRENT_TIMESTAMP'
    return 'STRFTIME'


def _models():
    User = get_user_model()

    class Sheet(PermittedUsersMixin, models.Model):
        objects = models.Manager.from_queryset(PermittedQuerySet)()
        title = models.CharField(max_length=40, null=True)
        expires_at = models.DateTimeField(null=True)
        opened_on = models.DateField(null=True)
        rank = models.IntegerField(null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_sheet'

    class SheetGrant(models.Model):
        sheet = models.ForeignKey(Sheet, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_grant'

    class SheetPass(models.Model):
        sheet = models.ForeignKey(Sheet, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        sponsor = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permissions = models.ManyToManyField(Permission, related_name='+')
        expires_at = models.DateTimeField(null=True)
        label = models.CharField(max_length=40, null=True)
        opened_on = models.DateField(null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_pass'

    return Sheet, SheetGrant, SheetPass


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


@contextmanager
def _published(factory):
    factory.path = BACKEND
    with published_class_catalog(
        _SqlBackend, factory,
    ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
        yield


def _bind_permission_m2m(model):
    """isolate_apps does not always finish a many-to-many to Permission."""
    field = model._meta.get_field('permissions')
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(Permission, field.remote_field)


def _permission(model):
    return Permission.objects.get_or_create(
        content_type=ContentType.objects.get_for_model(model),
        codename='change_sheet',
        defaults={'name': 'Can change sheet'},
    )[0]


def _assert_stored(test, node):
    found = list(walk(node))
    for item in found:
        test.assertNotIsInstance(item.value, Symbol)
        value = item.value
        test.assertFalse(
            value is not None and hasattr(value, 'resolve_expression'),
        )
    return found


def _assert_lowered(test, node):
    found = _assert_stored(test, node)
    test.assertTrue(any(
        item.kind == 'call' and item.value == 'now' for item in found
    ))


def _queries(user, sheet):
    with CaptureQueriesContext(connection) as captured:
        user.has_perm(PERM, sheet)
    return captured.captured_queries


def _clock_queries(queries):
    token = _clock_token()
    return [row['sql'] for row in queries if token in row['sql'].upper()]


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FunctionRegisterTest(TransactionTestCase):
    """Registration lowers functions and rejects everything else."""

    def _pass_model(self):
        _Sheet, _Grant, Pass = _models()
        return Pass

    def _reject(self, builder, needle, *, named=False, model=None,
                functions=False):
        handle = compiler()
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionError) as caught:
                if named:
                    handle.add_named_filter(model, 'bad', builder)
                else:
                    handle.register(
                        trust=model, delegate='delegate', sponsor='sponsor',
                        content='sheet', condition=builder,
                    )
        self.assertIn(needle, str(caught.exception))
        if functions:
            self.assertIn('trusts.functions', str(caught.exception))
        self.assertEqual(handle.records, ())
        self.assertEqual(handle.delegations, ())

    def test_hash_stays_defined(self):
        self.assertIsNotNone(Now.__hash__)
        self.assertIsNotNone(Lower.__hash__)
        self.assertIsNotNone(Coalesce.__hash__)
        hash(Now())
        hash(Lower(Value('a')))
        hash(Coalesce(Value('a'), Value('b')))

    def test_docs_condition_lowers_with_zero_sql(self):
        Pass = self._pass_model()
        deadline = timezone.now()
        handle = compiler()
        with self.assertNumQueries(0):
            record = handle.register(
                trust=Pass, delegate='delegate', sponsor='sponsor',
                content='sheet',
                condition=lambda d, p: (
                    d.permissions.contains(p)
                    & (d.expires_at > Now())
                    & (Now() < d.expires_at)
                    & (Lower(d.label) == Lower(Value('BOB')))
                    & (Coalesce(d.expires_at, Value(deadline)) >= Now())
                    & (Lower(Coalesce(d.label, Value('x'))) == 'x')
                ),
            )
        _assert_lowered(self, record.condition)
        self.assertEqual(len(handle.delegations), 1)

    def test_django_lower_bool_names_trusts_functions(self):
        Pass = self._pass_model()
        self._reject(
            lambda d, p: DjangoLower(Value('A')) == DjangoLower(Value('B')),
            'Python bool', model=Pass, functions=True,
        )

    def test_django_now_is_rejected(self):
        Pass = self._pass_model()
        self._reject(
            lambda d, p: d.expires_at > DjangoNow(),
            'Now', model=Pass, functions=True,
        )

    def test_subclass_template_and_arity_are_rejected(self):
        Pass = self._pass_model()

        class Extra(Lower):
            pass

        cases = (
            (lambda d, p: Extra(d.label) == 'a', 'Extra'),
            (
                lambda d, p: Lower(d.label, output_field=CharField()) == 'a',
                'output_field',
            ),
            (lambda d, p: Lower(d.label, function='LOWER') == 'a', 'function'),
            (
                lambda d, p: Now(template='CURRENT_TIMESTAMP') < d.expires_at,
                'template',
            ),
            (lambda d, p: Now(d.label) < d.expires_at, 'takes no arguments'),
            (lambda d, p: Coalesce(d.label) == 'a', 'at least two'),
        )
        for builder, needle in cases:
            with self.subTest(needle=needle):
                self._reject(builder, needle, model=Pass, functions=True)

    def test_types_null_and_ambiguous_lookups_are_rejected(self):
        Sheet, _Grant, Pass = _models()
        cases = (
            (lambda d, p: Lower(d.expires_at) == 'a', 'accepts text', Pass, False),
            (
                lambda d, p: Coalesce(d.label, d.expires_at) == 'a',
                'field type', Pass, False,
            ),
            (lambda d, p: d.expires_at > None, 'NULL does not grant', Pass, False),  # noqa: E711
            (lambda d, p: Lower(d.label) == None, 'NULL does not grant', Pass, False),  # noqa: E711
            (lambda d, p: d.opened_on > Now(), 'DateTimeField', Pass, False),
            (
                lambda u, p, o: Lower(F('title')) == Lower(Value('a')),
                'not supported', Sheet, True,
            ),
            (lambda u, p, o: Lower('title') == 'a', 'not supported', Sheet, True),
            (lambda u, p, o: o.title == Value('a'), 'Value', Sheet, True),
        )
        for builder, needle, model, named in cases:
            with self.subTest(needle=needle):
                self._reject(
                    builder, needle, named=named, model=model,
                    functions=named and needle == 'Value',
                )

    def test_mixed_user_and_object_function_is_rejected_at_register(self):
        Sheet, _Grant, Pass = _models()
        self._reject(
            lambda u, p, o: Coalesce(u.username, o.title) == 'fallback',
            'mixes a user field and an object field',
            named=True, model=Sheet,
        )
        self._reject(
            lambda u, p, o: Coalesce(u.username, o.title) == Value('fallback'),
            'Value', named=True, model=Sheet, functions=True,
        )
        handle = compiler()
        with self.assertNumQueries(0):
            handle.add_named_filter(
                Sheet, 'sides',
                lambda u, p, o: Lower(u.username) == Lower(o.title),
            )
            handle.register(
                trust=Pass, delegate='delegate', sponsor='sponsor',
                content='sheet',
                condition=lambda d: Coalesce(d.label, Value('open')) == 'open',
            )
        self._reject(
            lambda d, p: Coalesce(d.label, p.codename) == 'x',
            'trust row', model=Pass,
        )

    def test_user_rules_reject_functions_and_ordering(self):
        handle = compiler()
        cases = (
            (lambda u: u.date_joined > Now(), 'Ordered comparison'),
            (lambda u: Lower(u.username) == 'a', 'An SQL function'),
            (lambda u: u.username < 'm', 'Ordered comparison'),
        )
        for builder, needle in cases:
            with self.subTest(needle=needle):
                with self.assertNumQueries(0):
                    with self.assertRaises(PermissionConditionError) as caught:
                        handle.set_user_condition('clock', builder)
                self.assertIn(needle, str(caught.exception))
                self.assertIn('user condition', str(caught.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FunctionAgreementTest(TransactionTestCase):
    """Live checks agree, and expiration stays on the delegation row."""

    def test_delegation_and_named_filters(self):
        User = get_user_model()
        Sheet, Grant, Pass = _models()
        _bind_permission_m2m(Pass)
        with _tables(Sheet, Grant, Pass):
            change = _permission(Sheet)
            alice = User.objects.create_user('alice-sqlfn', password='x')
            bob = User.objects.create_user('bob-sqlfn', password='x')
            carol = User.objects.create_user('carol-sqlfn', password='x')
            dave = User.objects.create_user('dave-sqlfn', password='x')
            erin = User.objects.create_user('erin-sqlfn', password='x')
            erin.is_active = False
            erin.save(update_fields=['is_active'])
            future = timezone.now() + timedelta(days=2)
            past = timezone.now() - timedelta(days=2)
            far = timezone.now() + timedelta(days=30)
            deadline = (timezone.now() - timedelta(days=10)).replace(microsecond=0)
            sheet = Sheet.objects.create(title='OPEN', expires_at=future, rank=3)
            Grant.objects.create(sheet=sheet, user=alice, permission=change)
            Grant.objects.create(sheet=sheet, user=carol, permission=change)
            bob_pass = Pass.objects.create(
                sheet=sheet, delegate=bob, sponsor=alice,
                expires_at=future, label='Open',
            )
            bob_pass.permissions.add(change)
            erin_pass = Pass.objects.create(
                sheet=sheet, delegate=erin, sponsor=alice,
                expires_at=future, label='Open',
            )
            erin_pass.permissions.add(change)
            users = (alice, bob, carol, dave)
            self._live_delegation(
                Sheet, Grant, Pass, change, sheet, alice, bob, carol, dave,
                erin, erin_pass, bob_pass, users, future, past,
            )
            self._coalesce_delegation(
                Sheet, Grant, Pass, change, sheet, alice, bob, carol,
                bob_pass, users, far,
            )
            self._exact_deadline(
                Sheet, Grant, Pass, change, sheet, alice, bob, carol,
                bob_pass, users, deadline,
            )
            self._named_filters(
                Sheet, Grant, change, alice, bob, erin, future, past, far,
            )
            self._policy(Grant, Pass)

    def _grant(self, factory, Grant):
        factory.register(
            trust=Grant, user='user', permission='permission', content='sheet',
        )

    def _register(self, Grant, Pass, condition):
        factory = compiler(path=BACKEND)
        self._grant(factory, Grant)
        with self.assertNumQueries(0):
            record = factory.register(
                trust=Pass, delegate='delegate', sponsor='sponsor',
                content='sheet', condition=condition,
            )
        _assert_stored(self, record.condition)
        return factory

    def _allowed(self, Pass, Grant, change, user, sheet, predicate):
        if Grant.objects.filter(
            sheet=sheet, user=user, permission=change,
        ).exists():
            return True
        row = Pass.objects.filter(sheet=sheet, delegate=user).first()
        if row is None:
            return False
        if not Grant.objects.filter(
            sheet=sheet, user=row.sponsor, permission=change,
        ).exists():
            return False
        return predicate(row, change)

    def _agree(self, Sheet, users, sheets, allowed, code=None):
        perm = PERM if code is None else '%s:%s' % (PERM, code)
        for user in users:
            expected = {row.pk for row in sheets if allowed(user, row)}
            with self.subTest(code=code, user=user.username, check='permitted'):
                if code is None:
                    listed = Sheet.objects.permitted(PERM, user)
                else:
                    listed = Sheet.objects.permitted(
                        PERM, user, conditions=(code,),
                    )
                self.assertEqual(
                    set(listed.values_list('pk', flat=True)), expected,
                )
            with self.subTest(code=code, user=user.username, check='has_perm'):
                held = {row.pk for row in sheets if user.has_perm(perm, row)}
                self.assertEqual(held, expected)
        for row in sheets:
            expected = {user.pk for user in users if allowed(user, row)}
            with self.subTest(code=code, row=row.pk, check='permitted_users'):
                found = row.get_permitted_users(perm)
                self.assertEqual(
                    set(found.values_list('pk', flat=True)), expected,
                )

    def _live_delegation(self, Sheet, Grant, Pass, change, sheet, alice, bob,
                         carol, dave, erin, erin_pass, bob_pass, users,
                         future, past):
        held = {
            bob_pass.pk: {change.pk},
            erin_pass.pk: {change.pk},
        }

        def live(row, permission):
            return (
                permission.pk in held.get(row.pk, ())
                and row.expires_at is not None
                and row.expires_at > timezone.now()
                and row.label is not None
                and row.label.lower() == 'open'
            )

        factory = self._register(
            Grant, Pass,
            lambda d, p: (
                d.permissions.contains(p)
                & (d.expires_at > Now())
                & (Lower(d.label) == Lower(Value('OPEN')))
            ),
        )
        sheets = (sheet,)

        def allowed(user, row):
            return self._allowed(Pass, Grant, change, user, row, live)

        with _published(factory):
            ContentType.objects.get_for_model(Sheet)
            self._agree(Sheet, users, sheets, allowed)
            backend = _SqlBackend()
            self.assertFalse(erin.has_perm(PERM, sheet))
            self.assertTrue(backend.has_perm(
                erin, PERM, sheet, skip_is_active=True,
            ))
            self.assertIn(
                erin.pk,
                set(sheet.get_permitted_users(
                    PERM, skip_is_active=True,
                ).values_list('pk', flat=True)),
            )
            self.assertNotIn(
                erin.pk,
                set(sheet.get_permitted_users(PERM).values_list('pk', flat=True)),
            )
            plain = compiler(path=BACKEND)
            self._grant(plain, Grant)
            plain.register(
                trust=Pass, delegate='delegate', sponsor='sponsor',
                content='sheet',
                condition=lambda d, p: d.permissions.contains(p),
            )
            with _published(plain):
                bob.has_perm(PERM, sheet)
                without = _queries(bob, sheet)
            with _published(factory):
                with_clock = _queries(bob, sheet)
            self.assertEqual(len(with_clock), len(without))
            clocked = _clock_queries(with_clock)
            self.assertTrue(clocked)
            self.assertIn('sqlfn_pass_permissions', '\n'.join(clocked))
            self.assertIsNone(_date_literal(clocked))
            Pass.objects.filter(pk=bob_pass.pk).update(expires_at=DjangoNow())
            bob_pass.refresh_from_db()
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertTrue(alice.has_perm(PERM, sheet))
            self.assertTrue(carol.has_perm(PERM, sheet))
            bob_pass.expires_at = future
            bob_pass.save(update_fields=['expires_at'])
            erin_pass.expires_at = past
            erin_pass.save(update_fields=['expires_at'])
            self.assertFalse(backend.has_perm(
                erin, PERM, sheet, skip_is_active=True,
            ))
            self.assertFalse(Sheet.objects.permitted(
                PERM, erin, skip_is_active=True,
            ).filter(pk=sheet.pk).exists())
            erin_pass.expires_at = future
            erin_pass.save(update_fields=['expires_at'])
            bob_pass.permissions.remove(change)
            held[bob_pass.pk].discard(change.pk)
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertTrue(carol.has_perm(PERM, sheet))
            bob_pass.permissions.add(change)
            held[bob_pass.pk].add(change.pk)
            Grant.objects.filter(user=alice, permission=change).delete()
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertFalse(backend.has_perm(
                erin, PERM, sheet, skip_is_active=True,
            ))
            self.assertTrue(carol.has_perm(PERM, sheet))
            Grant.objects.create(sheet=sheet, user=alice, permission=change)
            bob_pass.label = 'Shut'
            bob_pass.save(update_fields=['label'])
            self.assertFalse(bob.has_perm(PERM, sheet))
            bob_pass.label = 'OPEN'
            bob_pass.expires_at = past
            bob_pass.save(update_fields=['label', 'expires_at'])
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertTrue(alice.has_perm(PERM, sheet))
            bob_pass.expires_at = None
            bob_pass.save(update_fields=['expires_at'])
            self.assertFalse(bob.has_perm(PERM, sheet))
            bob_pass.expires_at = future
            bob_pass.save(update_fields=['expires_at'])

    def _coalesce_delegation(self, Sheet, Grant, Pass, change, sheet, alice,
                             bob, carol, bob_pass, users, far):
        def fallback(row, permission):
            expires = row.expires_at if row.expires_at is not None else far
            label = row.label if row.label is not None else 'OPEN'
            return expires > timezone.now() and label.lower() == 'open'

        def condition(d, p):
            return (
                d.permissions.contains(p)
                & (Coalesce(d.expires_at, Value(far)) > Now())
                & (Lower(Coalesce(d.label, Value('OPEN'))) == 'open')
            )

        factory = self._register(Grant, Pass, condition)
        bob_pass.expires_at = None
        bob_pass.label = None
        bob_pass.save(update_fields=['expires_at', 'label'])

        def allowed(user, row):
            return self._allowed(Pass, Grant, change, user, row, fallback)

        with _published(factory):
            self._agree(Sheet, users, (sheet,), allowed)
            self.assertTrue(bob.has_perm(PERM, sheet))
            bob_pass.expires_at = timezone.now() - timedelta(days=2)
            bob_pass.save(update_fields=['expires_at'])
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertTrue(carol.has_perm(PERM, sheet))

    def _exact_deadline(self, Sheet, Grant, Pass, change, sheet, alice, bob,
                        carol, bob_pass, users, deadline):
        bob_pass.expires_at = deadline
        bob_pass.label = 'OPEN'
        bob_pass.save(update_fields=['expires_at', 'label'])
        bob_pass.refresh_from_db()
        stored = bob_pass.expires_at

        def _match(op):
            def predicate(row, permission):
                if row.expires_at is None:
                    return False
                if op == 'gt':
                    return row.expires_at > stored
                return row.expires_at >= stored
            return predicate

        def later_than(d, p):
            return d.permissions.contains(p) & (d.expires_at > deadline)

        def at_deadline(d, p):
            return d.permissions.contains(p) & (d.expires_at >= deadline)

        later = self._register(Grant, Pass, later_than)
        exact = self._register(Grant, Pass, at_deadline)
        with _published(later):
            self.assertFalse(bob.has_perm(PERM, sheet))
            self.assertTrue(alice.has_perm(PERM, sheet))
            self._agree(
                Sheet, users, (sheet,),
                lambda user, row: self._allowed(
                    Pass, Grant, change, user, row, _match('gt'),
                ),
            )
        with _published(exact):
            self.assertTrue(bob.has_perm(PERM, sheet))
            self._agree(
                Sheet, users, (sheet,),
                lambda user, row: self._allowed(
                    Pass, Grant, change, user, row, _match('ge'),
                ),
            )

    def _named_filters(self, Sheet, Grant, change, alice, bob, erin, future,
                       past, far):
        Grant.objects.all().delete()
        live = Sheet.objects.create(title='OPEN', expires_at=future, rank=3)
        expired = Sheet.objects.create(title='OPEN', expires_at=past, rank=3)
        shut = Sheet.objects.create(title='SHUT', expires_at=future, rank=0)
        blank = Sheet.objects.create(title=None, expires_at=None, rank=None)
        named = Sheet.objects.create(
            title='ALICE-SQLFN', expires_at=future, rank=4,
        )
        rows = (live, expired, shut, blank, named)
        for row in rows:
            Grant.objects.create(sheet=row, user=alice, permission=change)
            Grant.objects.create(sheet=row, user=bob, permission=change)
        Grant.objects.create(sheet=live, user=erin, permission=change)
        granted = {alice.pk, bob.pk}
        now = timezone.now()
        filters = (
            (
                'fresh',
                lambda u, p, o: o.expires_at > Now(),
                lambda user, row: (
                    user.pk in granted
                    and row.expires_at is not None
                    and row.expires_at > now
                ),
            ),
            (
                'titled',
                lambda u, p, o: Lower(o.title) == Lower(Value('OPEN')),
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() == 'open'
                ),
            ),
            (
                'other',
                lambda u, p, o: Lower(o.title) != Lower(Value('OPEN')),
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() != 'open'
                ),
            ),
            (
                'fallback',
                lambda u, p, o: Coalesce(o.expires_at, Value(far)) > Now(),
                lambda user, row: user.pk in granted and (
                    far > now if row.expires_at is None else row.expires_at > now
                ),
            ),
            (
                'ranked',
                lambda u, p, o: (o.rank >= 1) & (o.rank < 5),
                lambda user, row: (
                    user.pk in granted
                    and row.rank is not None
                    and 1 <= row.rank < 5
                ),
            ),
            (
                'who',
                lambda u, p, o: Lower(u.username) == Lower(o.title),
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() == user.username.lower()
                ),
            ),
            (
                'nested',
                lambda u, p, o: (
                    Lower(Coalesce(o.title, Value('OPEN'))) == 'open'
                ),
                lambda user, row: user.pk in granted and (
                    'open' if row.title is None else row.title.lower()
                ) == 'open',
            ),
            (
                'early',
                lambda u, p, o: (u.username < 'b') & (u.date_joined <= now),
                lambda user, row: (
                    user.pk in granted
                    and user.username < 'b'
                    and user.date_joined <= now
                ),
            ),
        )
        factory = compiler(path=BACKEND)
        self._grant(factory, Grant)
        with self.assertNumQueries(0):
            for code, builder, _predicate in filters:
                factory.add_named_filter(Sheet, code, builder)
        with _published(factory):
            for code, _builder, predicate in filters:
                self._agree(
                    Sheet, (alice, bob), rows, predicate, code=code,
                )
            backend = _SqlBackend()
            colon = '%s:fresh' % PERM
            self.assertFalse(erin.has_perm(colon, live))
            self.assertTrue(backend.has_perm(
                erin, colon, live, skip_is_active=True,
            ))
            self.assertTrue(Sheet.objects.permitted(
                PERM, erin, conditions=('fresh',), skip_is_active=True,
            ).filter(pk=live.pk).exists())
            self.assertFalse(backend.has_perm(
                erin, colon, expired, skip_is_active=True,
            ))
            self.assertIn(
                erin.pk,
                set(live.get_permitted_users(
                    colon, skip_is_active=True,
                ).values_list('pk', flat=True)),
            )
            self.assertNotIn(
                erin.pk,
                set(expired.get_permitted_users(
                    colon, skip_is_active=True,
                ).values_list('pk', flat=True)),
            )

    def _policy(self, Grant, Pass):
        factory = compiler(path=BACKEND)
        self._grant(factory, Grant)
        factory.register(
            trust=Pass, delegate='delegate', sponsor='sponsor',
            content='sheet',
            condition=lambda d, p: (
                d.permissions.contains(p)
                & (d.expires_at > Now())
                & (Lower(d.label) == Lower(Value('OPEN')))
                & (Coalesce(d.label, Value('OPEN')) == 'open')
            ),
        )
        raw = render_configured_policy(factory)
        text = raw.decode('utf-8')
        self.assertIn(_clock_token(), text.upper())
        self.assertIn('LOWER', text.upper())
        self.assertIn('COALESCE', text.upper())
        self.assertIn('Now()', text)
        self.assertIn('Lower(', text)
        self.assertIn('Coalesce(', text)
        self.assertIsNone(_date_literal([text]))


def _date_literal(parts):
    matched = re.search(r'20\d{2}-\d{2}-\d{2}', '\n'.join(parts))
    if matched is None:
        return None
    return matched.group(0)


def _py_op(op, left, right):
    if op == '==':
        return left == right
    if op == '!=':
        return left != right
    if op == '<':
        return left < right
    if op == '<=':
        return left <= right
    if op == '>':
        return left > right
    return left >= right


def _tree_op(op, left, right):
    if op == '==':
        return left == right
    if op == '!=':
        return left != right
    if op == '<':
        return left < right
    if op == '<=':
        return left <= right
    if op == '>':
        return left > right
    return left >= right


_MATRIX_OPS = ('==', '!=', '<', '<=', '>', '>=')


def _wide_models():
    User = get_user_model()

    class Wide(PermittedUsersMixin, models.Model):
        objects = models.Manager.from_queryset(PermittedQuerySet)()
        chars = models.CharField(max_length=20, null=True)
        notes = models.TextField(null=True)
        rank = models.IntegerField(null=True)
        big = models.BigIntegerField(null=True)
        small = models.SmallIntegerField(null=True)
        positive = models.PositiveIntegerField(null=True)
        amount = models.DecimalField(
            max_digits=8, decimal_places=2, null=True,
        )
        ratio = models.FloatField(null=True)
        opened = models.DateField(null=True)
        expires = models.DateTimeField(null=True)
        flag = models.BooleanField(null=True)
        owner = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_wide'

    class WideGrant(models.Model):
        wide = models.ForeignKey(Wide, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_wide_grant'

    class WidePass(models.Model):
        wide = models.ForeignKey(Wide, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        sponsor = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        notes = models.TextField(null=True)
        big = models.BigIntegerField(null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'sqlfn_wide_pass'

    return Wide, WideGrant, WidePass


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FunctionMatrixTest(TransactionTestCase):
    """Every function shape agrees across the three APIs, or dies at register."""

    def test_mismatched_coalesce_is_rejected_at_register(self):
        Wide, _Grant, _Pass = _wide_models()
        rejected = (
            (lambda u, p, o: Coalesce(o.notes, o.chars) == 'a', 'field type'),
            (lambda u, p, o: Coalesce(o.big, o.rank) == 0, 'field type'),
            (lambda u, p, o: Coalesce(Value(0), o.notes) == 'a', 'share one type'),
            (lambda u, p, o: Coalesce(o.owner, Value(0)) == 0, 'relation'),
            (lambda u, p, o: Coalesce(o.opened, Now()) > Now(), 'field type'),
        )
        for builder, needle in rejected:
            with self.subTest(needle=needle):
                handle = compiler()
                with self.assertNumQueries(0):
                    with self.assertRaises(PermissionConditionError) as caught:
                        handle.add_named_filter(Wide, 'bad', builder)
                self.assertIn(needle, str(caught.exception))
                self.assertEqual(handle.records, ())

    def test_shapes_agree_or_reject_at_register(self):
        User = get_user_model()
        Wide, Grant, Pass = _wide_models()
        future = (timezone.now() + timedelta(days=2)).replace(microsecond=0)
        past = (timezone.now() - timedelta(days=2)).replace(microsecond=0)
        opened = date(2024, 6, 1)
        earlier = date(2020, 1, 1)
        columns = (
            ('chars', 'a', 'm', True),
            ('notes', 'a', 'm', True),
            ('rank', 0, 3, True),
            ('big', 0, 3, True),
            ('small', 0, 3, True),
            ('positive', 0, 3, True),
            ('amount', Decimal('0'), Decimal('2.50'), True),
            ('ratio', 0, 2.5, True),
            ('opened', earlier, opened, True),
            ('expires', past, future, True),
            ('flag', False, True, False),
        )
        text = ('chars', 'notes')
        must_work = []
        must_reject = []
        for name, fallback, sample, ordered in columns:
            ops = _MATRIX_OPS if ordered else ('==', '!=')
            for value_first in (False, True):
                for op in ops:
                    must_work.append((
                        'coalesce %s %s %s' % (
                            name, 'value' if value_first else 'field', op,
                        ),
                        _coalesce_builder(name, fallback, sample, op, value_first),
                        _coalesce_expect(name, fallback, sample, op, value_first),
                    ))
            if not ordered:
                must_reject.append((
                    'ordered %s' % name,
                    _coalesce_builder(name, fallback, sample, '<', False),
                ))
        for name, _fallback, sample, ordered in columns:
            if name in text:
                for op in _MATRIX_OPS:
                    must_work.append((
                        'lower %s %s' % (name, op),
                        _lower_builder(name, sample, op),
                        _lower_expect(name, sample, op),
                    ))
            else:
                must_reject.append((
                    'lower %s' % name,
                    lambda u, p, o, name=name: Lower(getattr(o, name)) == 'a',
                ))
        for op in _MATRIX_OPS:
            must_work.append((
                'now expires %s' % op,
                _now_builder('expires', op, False),
                _now_expect(op, False),
            ))
        for name, _fallback, _sample, _ordered in columns:
            if name == 'expires':
                continue
            must_reject.append((
                'now %s' % name,
                lambda u, p, o, name=name: getattr(o, name) > Now(),
            ))
        must_work.extend(_root_cases())
        must_work.extend(_pair_cases(future))
        must_reject.extend((
            ('notes with chars', lambda u, p, o: Coalesce(o.notes, o.chars) == 'a'),
            ('big with rank', lambda u, p, o: Coalesce(o.big, o.rank) == 0),
            ('notes with int', lambda u, p, o: Coalesce(o.notes, Value(1)) == 1),
            ('relation', lambda u, p, o: Coalesce(o.owner, Value(0)) == 0),
            ('date with now', lambda u, p, o: Coalesce(o.opened, Now()) > Now()),
            ('mixed roots', lambda u, p, o: Coalesce(u.username, o.notes) == 'a'),
            ('ordered active', lambda u, p, o: u.is_active < True),  # noqa: E712
        ))
        with _tables(Wide, Grant, Pass):
            change = _permission(Wide)
            user = User.objects.create_user('matrix-sqlfn', password='x')
            user.date_joined = past
            user.save(update_fields=['date_joined'])
            filled = Wide.objects.create(
                chars='m', notes='m', rank=3, big=3, small=3, positive=3,
                amount=Decimal('2.50'), ratio=2.5, opened=opened,
                expires=future, flag=True, owner=user,
            )
            blank = Wide.objects.create(
                chars=None, notes=None, rank=None, big=None, small=None,
                positive=None, amount=None, ratio=None, opened=None,
                expires=None, flag=None, owner=None,
            )
            for row in (filled, blank):
                Grant.objects.create(wide=row, user=user, permission=change)
            past_row = Wide.objects.create(expires=past)
            Grant.objects.create(wide=past_row, user=user, permission=change)
            rows = (filled, blank, past_row)
            factory = compiler(path=BACKEND)
            factory.register(
                trust=Grant, user='user', permission='permission',
                content='wide',
            )
            for label, builder in must_reject:
                with self.subTest(label=label, phase='reject'):
                    with self.assertNumQueries(0):
                        with self.assertRaises(PermissionConditionError):
                            factory.add_named_filter(Wide, 'bad', builder)
            accepted = []
            for index, (label, builder, expect) in enumerate(must_work):
                code = 'm%s' % index
                with self.subTest(label=label, phase='register'):
                    with self.assertNumQueries(0):
                        factory.add_named_filter(Wide, code, builder)
                    accepted.append((code, label, expect))
            codename = 'trusts_tests.change_sheet'
            with _published(factory):
                for code, label, expect in accepted:
                    with self.subTest(label=label, phase='agree'):
                        _agree_filter(
                            self, Wide, rows, user, code,
                            lambda row, user, expect=expect, codename=codename: (
                                expect(row, user)
                            ),
                        )
            self._delegation(Wide, Grant, Pass, user, filled)

    def _delegation(self, Wide, Grant, Pass, user, sheet):
        other = get_user_model().objects.create_user('matrix-other', password='x')
        live = Pass.objects.create(
            wide=sheet, delegate=other, sponsor=user, notes=None, big=None,
        )
        rejected = compiler(path=BACKEND)
        with self.assertNumQueries(0):
            with self.assertRaises(PermissionConditionError):
                rejected.register(
                    trust=Pass, delegate='delegate', sponsor='sponsor',
                    content='wide',
                    condition=lambda d: Coalesce(d.notes, Value(0)) == 0,
                )
        cases = []
        for value_first in (False, True):
            for op in _MATRIX_OPS:
                side = 'value' if value_first else 'field'
                cases.append((
                    'text %s %s' % (side, op),
                    _deleg_call('notes', 'a', value_first, op),
                    lambda row, op=op, value_first=value_first: _py_op(
                        op,
                        'a' if value_first or row.notes is None else row.notes,
                        'a',
                    ),
                ))
                cases.append((
                    'big %s %s' % (side, op),
                    _deleg_call('big', 0, value_first, op),
                    lambda row, op=op, value_first=value_first: _py_op(
                        op,
                        0 if value_first or row.big is None else row.big,
                        0,
                    ),
                ))
        cases.append((
            'lower',
            lambda d: Lower(Coalesce(d.notes, Value('A'))) == 'a',
            lambda row: (row.notes or 'A').lower() == 'a',
        ))
        for label, builder, expect in cases:
            factory = compiler(path=BACKEND)
            factory.register(
                trust=Grant, user='user', permission='permission',
                content='wide',
            )
            with self.assertNumQueries(0):
                factory.register(
                    trust=Pass, delegate='delegate', sponsor='sponsor',
                    content='wide', condition=builder,
                )
            with _published(factory):
                with self.subTest(label='delegation %s' % label):
                    self.assertIs(
                        other.has_perm(PERM, sheet), expect(live),
                    )
                    listed = Wide.objects.permitted(PERM, other)
                    self.assertEqual(
                        set(listed.values_list('pk', flat=True)),
                        {sheet.pk} if expect(live) else set(),
                    )
                    found = sheet.get_permitted_users(PERM)
                    self.assertEqual(
                        other.pk in set(found.values_list('pk', flat=True)),
                        expect(live),
                    )


def _coalesce_builder(name, fallback, sample, op, value_first):
    def builder(u, p, o, name=name, fallback=fallback, sample=sample,
                op=op, value_first=value_first):
        column = getattr(o, name)
        call = (
            Coalesce(Value(fallback), column)
            if value_first else Coalesce(column, Value(fallback))
        )
        return _tree_op(op, call, sample)
    return builder


def _coalesce_expect(name, fallback, sample, op, value_first):
    def expect(row, user, name=name, fallback=fallback, sample=sample, op=op,
               value_first=value_first):
        # A leading Value() is never NULL, so COALESCE keeps it.
        if value_first:
            value = fallback
        else:
            value = getattr(row, name)
            if value is None:
                value = fallback
        return _py_op(op, value, sample)
    return expect


def _lower_builder(name, sample, op):
    folded = sample.lower()

    def builder(u, p, o, name=name, folded=folded, op=op):
        return _tree_op(op, Lower(getattr(o, name)), folded)
    return builder


def _lower_expect(name, sample, op):
    folded = sample.lower()

    def expect(row, user, name=name, folded=folded, op=op):
        value = getattr(row, name)
        if value is None:
            return False
        return _py_op(op, value.lower(), folded)
    return expect


def _now_builder(name, op, clock):
    def builder(u, p, o, name=name, op=op):
        return _tree_op(op, getattr(o, name), Now())
    return builder


def _now_expect(op, clock):
    def expect(row, user, op=op):
        if row.expires is None:
            return False
        return _py_op(op, row.expires, timezone.now())
    return expect


def _root_cases():
    codename = 'trusts_tests.change_sheet'
    cases = []
    for value_first in (False, True):
        side = 'value' if value_first else 'field'
        for op in _MATRIX_OPS:
            cases.append((
                'user id %s %s' % (side, op),
                _user_id_builder(op, value_first),
                lambda row, user, op=op, value_first=value_first: _py_op(
                    op, 0 if value_first else user.pk, user.pk,
                ),
            ))
            cases.append((
                'owner id %s %s' % (side, op),
                _owner_builder(op, value_first),
                lambda row, user, op=op, value_first=value_first: _py_op(
                    op,
                    0 if value_first or row.owner_id is None else row.owner_id,
                    user.pk,
                ),
            ))
    for op in _MATRIX_OPS:
        cases.append((
            'user name %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(u.username, Value('a')), u.username,
            ),
            lambda row, user, op=op: _py_op(op, user.username, user.username),
        ))
        cases.append((
            'user lower %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Lower(u.username), Lower(Value('matrix-sqlfn')),
            ),
            lambda row, user, op=op: _py_op(
                op, user.username.lower(), user.username.lower(),
            ),
        ))
        cases.append((
            'user joined %s' % op,
            lambda u, p, o, op=op: _tree_op(op, u.date_joined, Now()),
            lambda row, user, op=op: _py_op(
                op, user.date_joined, timezone.now(),
            ),
        ))
        cases.append((
            'permission %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(p, Value('x')), codename,
            ),
            lambda row, user, op=op: _py_op(op, codename, codename),
        ))
        cases.append((
            'nested text %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Lower(Coalesce(o.notes, Value('A'))), 'm',
            ),
            lambda row, user, op=op: _py_op(
                op, (row.notes or 'A').lower(), 'm',
            ),
        ))
        cases.append((
            'nested lower %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(Lower(o.notes), Value('a')), 'm',
            ),
            lambda row, user, op=op: _py_op(
                op, 'a' if row.notes is None else row.notes.lower(), 'm',
            ),
        ))
    for op in ('==', '!='):
        cases.append((
            'user active %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(u.is_active, Value(False)), True,
            ),
            lambda row, user, op=op: _py_op(op, True, True),
        ))
    return cases


def _owner_builder(op, value_first):
    def builder(u, p, o, op=op, value_first=value_first):
        call = (
            Coalesce(Value(0), o.owner_id)
            if value_first else Coalesce(o.owner_id, Value(0))
        )
        return _tree_op(op, call, u.id)
    return builder


def _pair_cases(mark):
    """Two function calls, and a column coalesced with Now() or the permission."""
    cases = []
    for op in _MATRIX_OPS:
        cases.append((
            'lower both %s' % op,
            lambda u, p, o, op=op: _tree_op(op, Lower(o.chars), Lower(o.notes)),
            lambda row, user, op=op: (
                False if row.chars is None or row.notes is None
                else _py_op(op, row.chars.lower(), row.notes.lower())
            ),
        ))
        cases.append((
            'int both %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(o.rank, Value(0)), Coalesce(o.big, Value(0)),
            ),
            lambda row, user, op=op: _py_op(
                op,
                0 if row.rank is None else row.rank,
                0 if row.big is None else row.big,
            ),
        ))
        cases.append((
            'expires with now %s' % op,
            lambda u, p, o, op=op, mark=mark: _tree_op(
                op, Coalesce(o.expires, Now()), mark,
            ),
            lambda row, user, op=op, mark=mark: _py_op(
                op,
                timezone.now() if row.expires is None else row.expires,
                mark,
            ),
        ))
        cases.append((
            'permission field %s' % op,
            lambda u, p, o, op=op: _tree_op(
                op, Coalesce(o.chars, p), 'm',
            ),
            lambda row, user, op=op: _py_op(
                op,
                row.chars if row.chars is not None else 'trusts_tests.change_sheet',
                'm',
            ),
        ))
    return cases


def _deleg_call(name, fallback, value_first, op):
    def builder(d):
        column = getattr(d, name)
        call = (
            Coalesce(Value(fallback), column)
            if value_first else Coalesce(column, Value(fallback))
        )
        return _tree_op(op, call, fallback)
    return builder


def _user_id_builder(op, value_first):
    def builder(u, p, o, op=op, value_first=value_first):
        call = (
            Coalesce(Value(0), u.id) if value_first else Coalesce(u.id, Value(0))
        )
        return _tree_op(op, call, u.id)
    return builder


def _agree_filter(test, model, rows, user, code, expect):
    colon = '%s:%s' % (PERM, code)
    wanted = {row.pk for row in rows if expect(row, user)}
    listed = model.objects.permitted(PERM, user, conditions=(code,))
    test.assertEqual(set(listed.values_list('pk', flat=True)), wanted)
    for row in rows:
        test.assertIs(user.has_perm(colon, row), row.pk in wanted)
        found = row.get_permitted_users(colon)
        test.assertEqual(
            set(found.values_list('pk', flat=True)),
            {user.pk} if row.pk in wanted else set(),
        )
