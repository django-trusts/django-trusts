"""#187: family-local OR between AnyPath and one OrderedFold.

Public ``register_relationship`` / ``register_ordered_fold`` may coexist
on one content terminal. Each family grants independently; OrderedFold
deny does not veto a relationship grant. Named filters stay overlays.
Unsupported OrderedFold renderer stays fail-closed.
"""

from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission as AuthPermission
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue100 import (
    ALLOW,
    DENY,
    _FoldRuntimeMixin,
    _direct_models,
    _handles,
    _perm,
    _postgres,
    _register_direct,
    _tables,
)
from tests.core.test_issue131 import _handle, _public_direct_fold
from trusts.core import (
    PlanQueryCompiler,
    Ref,
    TrustsConfigurationError,
    TrustsRegistry,
    all_match,
    common_permissions,
)
from trusts.query import AuthorizedManager


def _grant_model(Document, Permission):
    User = get_user_model()

    class Grant(models.Model):
        document = models.ForeignKey(Document, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Grant


def _register_both(registry, Grant, Ace, Permission, Document, *, fold_first=False):
    g = Ref(Grant)
    if fold_first:
        compiled = _register_direct(registry, Ace, Permission, Document)
        record = registry.register(
            content=g.document, user=g.user, permission=g.permission,
        )
    else:
        record = registry.register(
            content=g.document, user=g.user, permission=g.permission,
        )
        compiled = _register_direct(registry, Ace, Permission, Document)
    return record, compiled


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FamilyLocalOrRegistrationTest(SimpleTestCase):
    def test_public_both_orders_register_with_zero_sql(self):
        Permission, Document, Ace = _direct_models()
        Grant = _grant_model(Document, Permission)
        fold = _public_direct_fold(Ace, Permission, Document)

        relationship_first = _handle(path='tests.core.187-rel-first')
        relationship_first.register_relationship(
            Grant, user='user', permission='permission', content='document',
        )
        relationship_first.register_ordered_fold(Ace, fold)
        plan = relationship_first.registry.plan_for(Document)
        self.assertEqual(len(plan.records), 1)
        self.assertIsNotNone(plan.strategy)

        fold_first = _handle(path='tests.core.187-fold-first')
        fold_first.register_ordered_fold(Ace, fold)
        fold_first.register_relationship(
            Grant, user='user', permission='permission', content='document',
        )
        plan = fold_first.registry.plan_for(Document)
        self.assertEqual(len(plan.records), 1)
        self.assertIsNotNone(plan.strategy)

    def test_incompatible_permission_terminal_rejects_without_mutation(self):
        Permission, Document, Ace = _direct_models()
        User = get_user_model()

        class AuthGrant(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                AuthPermission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        g = Ref(AuthGrant)
        registry = TrustsRegistry()
        _register_direct(registry, Ace, Permission, Document)
        stored = registry.strategies
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'permission terminal',
        ):
            registry.register(
                content=g.document, user=g.user, permission=g.permission,
            )
        self.assertEqual(registry.records, ())
        self.assertEqual(registry.strategies, stored)

        other = TrustsRegistry()
        other.register(content=g.document, user=g.user, permission=g.permission)
        stored_records = other.records
        with self.assertRaisesRegex(
            TrustsConfigurationError, r'permission terminal',
        ):
            _register_direct(other, Ace, Permission, Document)
        self.assertEqual(other.records, stored_records)
        self.assertEqual(other.strategies, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FamilyLocalOrZeroSqlRegistrationTest(TransactionTestCase):
    def test_mixed_registration_is_zero_sql_both_orders(self):
        Permission, Document, Ace = _direct_models()
        Grant = _grant_model(Document, Permission)
        with _tables(Permission, Document, Ace, Grant):
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                _register_both(registry, Grant, Ace, Permission, Document)
            self.assertEqual(len(registry.records), 1)
            self.assertEqual(len(registry.strategies), 1)
            other = TrustsRegistry()
            with self.assertNumQueries(0):
                _register_both(
                    other, Grant, Ace, Permission, Document, fold_first=True,
                )
            self.assertEqual(len(other.records), 1)
            self.assertEqual(len(other.strategies), 1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FamilyLocalOrVendorGateTest(TransactionTestCase):
    def test_mixed_plan_does_not_drop_unsupported_fold_branch(self):
        if _postgres():
            self.skipTest('vendor gate is the non-PostgreSQL path')
        Permission, Document, Ace = _direct_models()
        Grant = _grant_model(Document, Permission)
        with _tables(Permission, Document, Ace, Grant):
            User = get_user_model()
            alice = User.objects.create_user('alice-187-vendor', password='x')
            doc = Document.objects.create(title='kept')
            read = _perm(Permission, 'read', Document)
            Grant.objects.create(document=doc, user=alice, permission=read)
            Ace.objects.create(
                document=doc, ace_order=0, ace_type=DENY,
                access_mask=0x1, user=alice,
            )
            registry = TrustsRegistry()
            _register_both(registry, Grant, Ace, Permission, Document)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.has_permission(alice, doc, read)
            message = str(ctx.exception).lower()
            self.assertIn('postgresql', message)
            self.assertNotIn('with recursive', message)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FamilyLocalOrAuthorizationTest(_FoldRuntimeMixin, TransactionTestCase):
    def setUp(self):
        self.Permission, self.Document, self.Ace = _direct_models()
        self.Grant = _grant_model(self.Document, self.Permission)
        self._table_cm = _tables(
            self.Permission, self.Document, self.Ace, self.Grant,
        )
        self._table_cm.__enter__()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-187', password='x')
        self.bob = User.objects.create_user('bob-187', password='x')
        self.read = _perm(self.Permission, 'read', self.Document)
        self.doc = self.Document.objects.create(title='kept')
        self.other = self.Document.objects.create(title='other')
        self.nope = self.Document.objects.create(title='nope')

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _ace(self, *, order, polarity, mask, user=None, document=None):
        return self.Ace.objects.create(
            document=document or self.doc,
            ace_order=order,
            ace_type=polarity,
            access_mask=mask,
            user=user or self.alice,
        )

    def _grant(self, *, user=None, document=None, permission=None):
        return self.Grant.objects.create(
            document=document or self.doc,
            user=user or self.alice,
            permission=permission or self.read,
        )

    def _registry(self, *, fold_first=False, titled=False):
        registry = TrustsRegistry()
        _register_both(
            registry, self.Grant, self.Ace, self.Permission, self.Document,
            fold_first=fold_first,
        )
        if titled:
            _handle(registry).add_named_filter(
                self.Document, 'titled',
                lambda u, p, o: o.title != 'nope',
            )
        return registry

    def test_relationship_grant_survives_orderedfold_deny_both_orders(self):
        self._grant()
        self._ace(order=0, polarity=DENY, mask=0x1)
        for fold_first in (False, True):
            registry = self._registry(fold_first=fold_first)
            self._agree(registry, self.alice, self.read, self.doc, True)
            self._agree(registry, self.alice, self.read, self.other, False)
            self._agree(registry, self.bob, self.read, self.doc, False)

    def test_orderedfold_grant_survives_relationship_miss_both_orders(self):
        self._ace(order=0, polarity=ALLOW, mask=0x1)
        for fold_first in (False, True):
            registry = self._registry(fold_first=fold_first)
            self._agree(registry, self.alice, self.read, self.doc, True)
            self._agree(registry, self.bob, self.read, self.doc, False)

    def test_both_miss_or_deny_is_denied(self):
        self._ace(order=0, polarity=DENY, mask=0x1)
        registry = self._registry()
        self._agree(registry, self.alice, self.read, self.doc, False)

    def test_named_filter_overlay_still_restricts(self):
        self._grant(document=self.doc)
        self._grant(document=self.nope)
        self._ace(order=0, polarity=DENY, mask=0x1)
        self._ace(order=0, polarity=DENY, mask=0x1, document=self.nope)
        registry = self._registry(titled=True)
        self._agree(registry, self.alice, self.read, self.doc, True)
        self.assertTrue(registry.has_permission(self.alice, self.nope, self.read))
        handles = _handles(registry)
        extra = registry.compile_registered_condition_q(
            self.Document, 'trusts_tests.read_document:titled', self.alice,
        )
        with self.assertNumQueries(1):
            self.assertTrue(all_match(
                handles, self.doc, self.alice, self.read, extra_q=extra,
            ))
        with self.assertNumQueries(1):
            self.assertFalse(all_match(
                handles, self.nope, self.alice, self.read, extra_q=extra,
            ))
        with self.assertNumQueries(1):
            self.assertEqual(
                {row.pk for row in registry.filter_authorized(
                    self.Document.objects.all(), self.alice, self.read,
                )},
                {self.doc.pk, self.nope.pk},
            )
        titled_qs = registry.filter_authorized(
            self.Document.objects.all(), self.alice, self.read,
        ).filter(extra)
        with self.assertNumQueries(1):
            self.assertEqual({row.pk for row in titled_qs}, {self.doc.pk})

    def test_each_evaluated_projection_is_one_sql(self):
        self._grant()
        self._ace(order=0, polarity=DENY, mask=0x1)
        registry = self._registry()
        handles = _handles(registry)
        with self.assertNumQueries(0):
            qs = registry.filter_authorized(
                self.Document.objects.all(), self.alice, self.read,
            )
            enumerated = registry.permissions_for(self.alice, self.doc)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual({row.pk for row in qs}, {self.doc.pk})
        with self.assertNumQueries(1):
            self.assertIn(self.read.pk, {row.pk for row in enumerated})
        with self.assertNumQueries(1):
            self.assertTrue(all_match(
                handles, self.doc, self.alice, self.read,
            ))
        sql = str(qs.query).upper()
        self.assertIn('EXISTS', sql)
        self.assertIn('WITH RECURSIVE', sql)


@skipUnless(_postgres(), 'OrderedFold renderer is PostgreSQL')
@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FamilyLocalOrGroupProjectionTest(TransactionTestCase):
    def test_group_slice_uses_only_membership_records(self):
        User = get_user_model()
        Permission, Document, Ace = _direct_models()

        class Team(models.Model):
            members = models.ManyToManyField(User)

            class Meta:
                app_label = 'trusts_tests'

        class TeamGrant(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Permission, Document, Ace, Team, TeamGrant):
            alice = User.objects.create_user('alice-187g', password='x')
            carol = User.objects.create_user('carol-187g', password='x')
            read = _perm(Permission, 'read', Document)
            doc = Document.objects.create(title='kept')
            team = Team.objects.create()
            team.members.add(alice)
            TeamGrant.objects.create(document=doc, team=team, permission=read)
            Ace.objects.create(
                document=doc, ace_order=0, ace_type=DENY,
                access_mask=0x1, user=alice,
            )
            Ace.objects.create(
                document=doc, ace_order=0, ace_type=ALLOW,
                access_mask=0x1, user=carol,
            )
            registry = TrustsRegistry()
            g = Ref(TeamGrant)
            registry.register(
                content=g.document, user=g.team.members, permission=g.permission,
            )
            _register_direct(registry, Ace, Permission, Document)
            handles = _handles(registry)
            compiler = PlanQueryCompiler()
            plan = registry.plan_for(doc, user=alice, permission=read)
            self.assertTrue(plan.records)
            self.assertIsNotNone(plan.strategy)
            self.assertIsNotNone(
                compiler.group_exists(plan, doc, alice, read),
            )
            with self.assertNumQueries(1):
                self.assertTrue(all_match(
                    handles, doc, alice, read, kind='complete',
                ))
            with self.assertNumQueries(1):
                self.assertTrue(all_match(
                    handles, doc, alice, read, kind='group',
                ))
            with self.assertNumQueries(1):
                self.assertTrue(all_match(
                    handles, doc, carol, read, kind='complete',
                ))
            with self.assertNumQueries(1):
                self.assertFalse(all_match(
                    handles, doc, carol, read, kind='group',
                ))
            complete = common_permissions(handles, doc, alice, kind='complete')
            group = common_permissions(handles, doc, alice, kind='group')
            with self.assertNumQueries(1):
                self.assertIn(read.pk, {row.pk for row in complete})
            with self.assertNumQueries(1):
                self.assertIn(read.pk, {row.pk for row in group})
            carol_group = common_permissions(handles, doc, carol, kind='group')
            with self.assertNumQueries(1):
                self.assertNotIn(read.pk, {row.pk for row in carol_group})
