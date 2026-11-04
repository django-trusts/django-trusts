"""SQL functions in relation, delegation, and named-filter conditions.

``Now``, ``Lower``, and ``Coalesce`` from ``trusts.functions`` lower at
register time. ``has_perm``, ``.permitted()``, and ``get_permitted_users``
read the same stored tree. Django's own functions are rejected there.
"""
import re
from contextlib import contextmanager
from datetime import timedelta

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
from trusts.plan.grammar import Symbol, Tree

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


def _walk(node, found):
    if isinstance(node, (Symbol, Tree)):
        found.append(node)
    if hasattr(node, 'resolve_expression'):
        found.append(node)
    if not isinstance(node, Tree):
        return
    for child in (node.left, node.right, node.item, node.value):
        if isinstance(child, tuple):
            for item in child:
                _walk(item, found)
        elif child is not None:
            _walk(child, found)


def _assert_stored(test, node):
    found = []
    _walk(node, found)
    for item in found:
        test.assertNotIsInstance(item, Symbol)
        test.assertFalse(hasattr(item, 'resolve_expression'))
    return found


def _assert_lowered(test, node):
    found = _assert_stored(test, node)
    test.assertTrue(any(
        isinstance(item, Tree) and item.kind == 'call' and item.value == 'now'
        for item in found
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
                    & (Lower('label') == 'x')
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

        self._reject(
            lambda d, p: Extra(d.label) == 'a', 'Extra',
            model=Pass, functions=True,
        )
        self._reject(
            lambda d, p: Lower(d.label, output_field=CharField()) == 'a',
            'output_field', model=Pass, functions=True,
        )
        self._reject(
            lambda d, p: Lower(d.label, function='LOWER') == 'a',
            'function', model=Pass, functions=True,
        )
        self._reject(
            lambda d, p: Now(template='CURRENT_TIMESTAMP') < d.expires_at,
            'template', model=Pass, functions=True,
        )
        self._reject(
            lambda d, p: Now(d.label) < d.expires_at,
            'takes no arguments', model=Pass, functions=True,
        )
        self._reject(
            lambda d, p: Coalesce(d.label) == 'a',
            'at least two', model=Pass, functions=True,
        )

    def test_types_null_and_ambiguous_lookups_are_rejected(self):
        Sheet, _Grant, Pass = _models()
        self._reject(
            lambda d, p: Lower(d.expires_at) == 'a',
            'accepts text', model=Pass,
        )
        self._reject(
            lambda d, p: Coalesce(d.label, d.expires_at) == 'a',
            'share one type', model=Pass,
        )
        self._reject(
            lambda d, p: d.expires_at > None,  # noqa: E711
            'does not accept None', model=Pass,
        )
        self._reject(
            lambda d, p: Lower(d.label) == None,  # noqa: E711
            'NULL does not grant', model=Pass,
        )
        self._reject(
            lambda d, p: d.opened_on > Now(),
            'DateTimeField', model=Pass,
        )
        self._reject(
            lambda u, p, o: Lower(F('title')) == Lower(Value('a')),
            'Use a symbolic field', named=True, model=Sheet,
        )
        self._reject(
            lambda u, p, o: Lower('title') == 'a',
            'Use a symbolic field', named=True, model=Sheet,
        )
        self._reject(
            lambda u, p, o: o.title == Value('a'),
            'Value', named=True, model=Sheet, functions=True,
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
            'requested permission', model=Pass,
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

    def _register(self, Grant, Pass, condition):
        factory = compiler(path=BACKEND)
        factory.register(
            trust=Grant, user='user', permission='permission', content='sheet',
        )
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

    def _agree(self, Sheet, users, sheets, allowed):
        for user in users:
            expected = {row.pk for row in sheets if allowed(user, row)}
            with self.subTest(user=user.username, check='permitted'):
                listed = Sheet.objects.permitted(PERM, user)
                self.assertEqual(
                    set(listed.values_list('pk', flat=True)), expected,
                )
            with self.subTest(user=user.username, check='has_perm'):
                held = {row.pk for row in sheets if user.has_perm(PERM, row)}
                self.assertEqual(held, expected)
        for row in sheets:
            expected = {user.pk for user in users if allowed(user, row)}
            with self.subTest(row=row.pk, check='permitted_users'):
                found = row.get_permitted_users(PERM)
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
            plain.register(
                trust=Grant, user='user', permission='permission',
                content='sheet',
            )
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
        factory = compiler(path=BACKEND)
        factory.register(
            trust=Grant, user='user', permission='permission', content='sheet',
        )
        with self.assertNumQueries(0):
            factory.add_named_filter(
                Sheet, 'fresh', lambda u, p, o: o.expires_at > Now(),
            )
            factory.add_named_filter(
                Sheet, 'titled',
                lambda u, p, o: Lower(o.title) == Lower(Value('OPEN')),
            )
            factory.add_named_filter(
                Sheet, 'other',
                lambda u, p, o: Lower(o.title) != Lower(Value('OPEN')),
            )
            def fallback(u, p, o):
                return Coalesce(o.expires_at, Value(far)) > Now()

            factory.add_named_filter(Sheet, 'fallback', fallback)
            factory.add_named_filter(
                Sheet, 'ranked',
                lambda u, p, o: (o.rank >= 1) & (o.rank < 5),
            )
            factory.add_named_filter(
                Sheet, 'who',
                lambda u, p, o: Lower(u.username) == Lower(o.title),
            )
            factory.add_named_filter(
                Sheet, 'nested',
                lambda u, p, o: (
                    Lower(Coalesce(o.title, Value('OPEN'))) == 'open'
                ),
            )
        granted = {alice.pk, bob.pk}
        now = timezone.now()
        cases = (
            (
                'fresh',
                lambda user, row: (
                    user.pk in granted
                    and row.expires_at is not None
                    and row.expires_at > now
                ),
            ),
            (
                'titled',
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() == 'open'
                ),
            ),
            (
                'other',
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() != 'open'
                ),
            ),
            (
                'fallback',
                lambda user, row: user.pk in granted and (
                    far > now if row.expires_at is None else row.expires_at > now
                ),
            ),
            (
                'ranked',
                lambda user, row: (
                    user.pk in granted
                    and row.rank is not None
                    and 1 <= row.rank < 5
                ),
            ),
            (
                'who',
                lambda user, row: (
                    user.pk in granted
                    and row.title is not None
                    and row.title.lower() == user.username.lower()
                ),
            ),
            (
                'nested',
                lambda user, row: user.pk in granted and (
                    'open' if row.title is None else row.title.lower()
                ) == 'open',
            ),
        )
        with _published(factory):
            for code, predicate in cases:
                self._filter_agree(
                    Sheet, (alice, bob), rows, code, predicate,
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

    def _filter_agree(self, Sheet, users, rows, code, predicate):
        colon = '%s:%s' % (PERM, code)
        for user in users:
            expected = {row.pk for row in rows if predicate(user, row)}
            with self.subTest(code=code, user=user.username, check='permitted'):
                listed = Sheet.objects.permitted(
                    PERM, user, conditions=(code,),
                )
                self.assertEqual(
                    set(listed.values_list('pk', flat=True)), expected,
                )
            with self.subTest(code=code, user=user.username, check='has_perm'):
                held = {row.pk for row in rows if user.has_perm(colon, row)}
                self.assertEqual(held, expected)
        for row in rows:
            expected = {user.pk for user in users if predicate(user, row)}
            with self.subTest(code=code, row=row.pk, check='permitted_users'):
                found = row.get_permitted_users(colon)
                self.assertEqual(
                    set(found.values_list('pk', flat=True)), expected,
                )

    def _policy(self, Grant, Pass):
        factory = compiler(path=BACKEND)
        factory.register(
            trust=Grant, user='user', permission='permission', content='sheet',
        )
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
