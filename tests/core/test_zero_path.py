"""Zero consumer of the composed AuthorizationPath seam (#43 Step 2).

Process-wide Content / Trust / Group / Role paths must go through
``compose`` at ``ContentQuerySet.permitted`` and object-level
``TrustModelBackend`` evaluation. Does not close #43. Does not relocate
concrete models.
"""

import inspect
from pathlib import Path

from django.contrib.auth.models import Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, TransactionTestCase

from trusts.zero.authorization import has_trust_row_perm
from trusts.zero.backends import TrustModelBackend, TrustModelBackendMixin
from trusts.context import Context
from trusts.zero.models import (
    Content,
    ContentQuerySet,
    Trust,
    TrustUserPermission,
    prepare_context_registry,
)
from trusts.path import AuthorizationPathError
from trusts.zero.query import (
    compose_zero_path,
    require_configured_operation,
    require_configured_requester,
    trust_grant_q,
)
from tests.models import Category, Organization, TestGroupJunction
from tests.support import (
    ContentModelMixin,
    enable_local_group_grant,
    reload_test_users,
)


def _query_source():
    import trusts.zero.query as query_mod
    return Path(inspect.getfile(query_mod)).read_text()


def _backend_source():
    return Path(inspect.getfile(TrustModelBackendMixin)).read_text()


class ZeroComposeConsumerSourceTest(TestCase):
    def test_permitted_uses_filter_authorized_not_parallel_join(self):
        source = inspect.getsource(ContentQuerySet.permitted)
        self.assertIn('filter_authorized', source)
        self.assertNotIn('compose_zero_path', source)
        self.assertNotIn('trust_grant_q', source)
        self.assertNotIn('Context.scope_path', source)

    def test_backend_object_path_uses_compose_not_filter_by_content(self):
        source = _backend_source()
        self.assertIn('compose_zero_path', source)
        self.assertIn('row_is_zero_granted', source)
        self.assertNotIn('filter_by_content', source)
        self.assertNotIn('_get_trusts', source)
        self.assertIn('Content.is_content', source)
        self.assertIn('GROUP_TRUSTEE', source)
        has_perm_src = inspect.getsource(TrustModelBackendMixin.has_perm)
        self.assertNotIn(
            'is_superuser',
            has_perm_src,
            'object-level has_perm must not short-circuit active superusers',
        )

    def test_deleted_noun_dependent_query_helpers_are_gone(self):
        source = _query_source()
        self.assertNotIn('group_local_grant_exists', source)
        self.assertNotIn('permission_granted_via_group_exists', source)
        self.assertNotIn('_never_exists', source)
        self.assertNotIn('TrustGroup', source)
        self.assertIn('compose', source)

    def test_no_trusts_schema_migration_added(self):
        migrations = Path(inspect.getfile(Trust)).resolve().parent / 'migrations'
        names = sorted(
            path.name for path in migrations.glob('*.py')
            if path.name != '__init__.py'
        )
        self.assertEqual(names, ['0001_initial.py', '0002_trustgroup.py'])


class ZeroComposeConsumerTest(ContentModelMixin, TestCase):
    def setUp(self):
        super(ZeroComposeConsumerTest, self).setUp()
        self.org = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Zero Org A',
        )
        self.org.save()
        self.org_b = Trust(
            settlor=self.user1, trust=Trust.objects.get_root(), title='Zero Org B',
        )
        self.org_b.save()
        self.content = self.create_content(self.org)
        self.content_b = self.create_content(self.org_b)
        TrustUserPermission.objects.get_or_create(
            trust=self.org, entity=self.user, permission=self.perm_read,
        )
        reload_test_users(self)

    def test_composed_path_matches_content_scope_hop(self):
        prepare_context_registry()
        path = compose_zero_path(Category, self.perm_read)
        self.assertIsNotNone(path)
        self.assertEqual(path.resource_to_scope, Context.scope_path(Category))
        self.assertEqual(path.resource_to_scope, 'trust')
        self.assertIn('direct', path.adapter_names)
        self.assertIn('group', path.adapter_names)

    def test_has_perm_and_permitted_agree_and_sql_filter(self):
        listed = set(
            Category.objects.permitted('read', self.user).values_list(
                'pk', flat=True,
            )
        )
        allowed = {
            obj.pk
            for obj in Category.objects.order_by('pk')
            if self.user.has_perm(self.get_perm_code(self.perm_read), obj)
        }
        self.assertEqual(listed, allowed)
        self.assertEqual(listed, {self.content.pk})
        qs = Category.objects.permitted('read', self.user)
        sql = str(qs.query)
        self.assertTrue(
            'JOIN' in sql.upper() or 'EXISTS' in sql.upper(),
            'permitted() must filter in SQL. SQL was: %s' % sql,
        )

    def test_permitted_is_fixed_query_after_permission_resolve(self):
        Category.objects.get_permission('read')
        with self.assertNumQueries(2):
            pks = list(
                Category.objects.permitted('read', self.user)
                .values_list('pk', flat=True)
            )
        self.assertEqual(pks, [self.content.pk])

    def test_has_perm_instance_is_fixed_query_after_permission_resolve(self):
        Category.objects.get_permission('read')
        with self.assertNumQueries(3):
            granted = self.user.has_perm(
                self.get_perm_code(self.perm_read), self.content,
            )
        self.assertTrue(granted)

    def test_group_and_role_ceiling_still_require_local_grant(self):
        self.perm_change.group_set.add(self.group)
        self.group.user_set.add(self.user)
        self.org.groups.add(self.group)
        reload_test_users(self)
        self.assertFalse(
            self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        )
        self.assertNotIn(
            self.content.pk,
            Category.objects.permitted('change', self.user).values_list(
                'pk', flat=True,
            ),
        )
        enable_local_group_grant(self.org, self.group, self.perm_change)
        reload_test_users(self)
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_change), self.content)
        )
        self.assertIn(
            self.content.pk,
            Category.objects.permitted('change', self.user).values_list(
                'pk', flat=True,
            ),
        )

    def test_junction_table_row_does_not_enter_has_perm(self):
        prepare_context_registry()
        junction = TestGroupJunction.objects.create(
            content=self.group, trust=self.org, name='zero-junction',
        )
        self.assertFalse(Content.is_content(junction))
        self.assertTrue(Context.is_registered(TestGroupJunction))
        self.assertTrue(
            self.user.has_perm(self.get_perm_code(self.perm_read), self.content)
        )
        self.assertFalse(
            self.user.has_perm(self.get_perm_code(self.perm_read), junction)
        )

    def test_get_all_permissions_uses_composed_scope(self):
        backend = TrustModelBackend()
        perms = backend.get_all_permissions(self.user, self.content)
        self.assertIn(self.get_perm_code(self.perm_read), perms)
        self.assertNotIn(self.get_perm_code(self.perm_change), perms)
        empty = backend.get_all_permissions(
            self.user, Category.objects.none(),
        )
        self.assertEqual(empty, [])

    def _read_perm(self):
        return self.get_perm_code(self.perm_read)

    def _permitted_pks(self, user):
        return set(
            Category.objects.permitted('read', user).values_list('pk', flat=True)
        )

    def _make_superuser(self, user):
        user.is_superuser = True
        user.is_active = True
        user.save()
        reload_test_users(self)
        return User._default_manager.get(pk=user.pk)

    def test_ungranted_superuser_absent_from_has_perm_and_permitted(self):
        superuser = self._make_superuser(self.user1)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)
        perm = self._read_perm()
        # Django User.has_perm still short-circuits before backends.
        self.assertTrue(superuser.has_perm(perm))
        backend = TrustModelBackend()
        self.assertFalse(backend.has_perm(superuser, perm, self.content))
        self.assertFalse(backend.has_perm(superuser, perm, self.content_b))
        listed = self._permitted_pks(superuser)
        self.assertNotIn(self.content.pk, listed)
        self.assertNotIn(self.content_b.pk, listed)
        allowed = {
            obj.pk
            for obj in Category.objects.order_by('pk')
            if backend.has_perm(superuser, perm, obj)
        }
        self.assertEqual(listed, allowed)

    def test_granted_superuser_present_in_has_perm_and_permitted(self):
        TrustUserPermission.objects.get_or_create(
            trust=self.org, entity=self.user1, permission=self.perm_read,
        )
        superuser = self._make_superuser(self.user1)
        perm = self._read_perm()
        backend = TrustModelBackend()
        self.assertTrue(backend.has_perm(superuser, perm, self.content))
        self.assertFalse(backend.has_perm(superuser, perm, self.content_b))
        listed = self._permitted_pks(superuser)
        self.assertEqual(listed, {self.content.pk})
        allowed = {
            obj.pk
            for obj in Category.objects.order_by('pk')
            if backend.has_perm(superuser, perm, obj)
        }
        self.assertEqual(listed, allowed)

    def test_superuser_junction_unregistered_and_unknown_perm_denied(self):
        superuser = self._make_superuser(self.user)
        perm = self._read_perm()
        backend = TrustModelBackend()
        self.assertTrue(backend.has_perm(superuser, perm, self.content))
        junction = TestGroupJunction.objects.create(
            content=self.group, trust=self.org, name='superuser-junction',
        )
        self.assertFalse(Content.is_content(junction))
        self.assertFalse(backend.has_perm(superuser, perm, junction))
        unregistered = Organization.objects.create(
            name='superuser-unregistered', manager=superuser,
        )
        self.assertFalse(Content.is_content(unregistered))
        self.assertFalse(Context.is_registered(Organization))
        self.assertFalse(backend.has_perm(superuser, perm, unregistered))
        unknown = '%s.nosuch_%s' % (self.app_label, self.model_name)
        self.assertFalse(backend.has_perm(superuser, unknown, self.content))


class ZeroSamePkFailClosedTest(ContentModelMixin, TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(ZeroSamePkFailClosedTest, self).setUp()
        self.org = Trust(
            settlor=self.user, trust=Trust.objects.get_root(),
            title='Same-PK org',
        )
        self.org.save()
        self.content = self.create_content(self.org)
        TrustUserPermission.objects.get_or_create(
            trust=self.org, entity=self.user, permission=self.perm_read,
        )
        reload_test_users(self)
        self.collider = Group.objects.create(pk=self.user.pk, name='same-pk-group')
        self.assertEqual(self.user.pk, self.collider.pk)

    def test_permitted_rejects_wrong_requester_same_pk(self):
        self.assertIn(
            self.content.pk,
            Category.objects.permitted('read', self.user).values_list(
                'pk', flat=True,
            ),
        )
        with self.assertRaises(AuthorizationPathError) as ctx:
            Category.objects.permitted('read', self.collider)
        self.assertIn('requester', str(ctx.exception))

    def test_permitted_rejects_raw_primary_key(self):
        with self.assertRaises(AuthorizationPathError) as ctx:
            Category.objects.permitted('read', self.user.pk)
        self.assertIn('primary key', str(ctx.exception).lower())

    def test_backend_has_perm_rejects_wrong_requester_same_pk(self):
        backend = TrustModelBackend()
        self.assertTrue(
            backend.has_perm(
                self.user, self.get_perm_code(self.perm_read), self.content,
            )
        )
        with self.assertRaises(AuthorizationPathError) as ctx:
            backend.has_perm(
                self.collider, self.get_perm_code(self.perm_read), self.content,
            )
        self.assertIn('requester', str(ctx.exception))

    def test_backend_has_perm_rejects_raw_primary_key_requester(self):
        backend = TrustModelBackend()
        with self.assertRaises(AuthorizationPathError):
            backend.has_perm(
                self.user.pk, self.get_perm_code(self.perm_read), self.content,
            )

    def test_filter_by_user_content_perm_rejects_wrong_requester_same_pk(self):
        qs = Trust.objects.filter_by_user_content_perm(
            self.user, Category, 'read',
        )
        self.assertIn(self.org.pk, qs.values_list('pk', flat=True))
        with self.assertRaises(AuthorizationPathError):
            list(Trust.objects.filter_by_user_content_perm(
                self.collider, Category, 'read',
            ))

    def test_has_trust_row_perm_rejects_wrong_requester_same_pk(self):
        trust_read = Trust.objects.get_permission('read')
        TrustUserPermission.objects.get_or_create(
            trust=self.org, entity=self.user, permission=trust_read,
        )
        reload_test_users(self)
        self.assertTrue(has_trust_row_perm(self.user, self.org, 'read'))
        with self.assertRaises(AuthorizationPathError):
            has_trust_row_perm(self.collider, self.org, 'read')

    def test_trust_grant_q_rejects_wrong_operation_same_pk(self):
        ct = ContentType.objects.get_for_model(Category)
        perm_same = Permission.objects.filter(pk=self.user.pk).first()
        if perm_same is None:
            perm_same = Permission.objects.create(
                pk=self.user.pk,
                content_type=ct,
                codename='zero_same_pk_perm',
                name='zero same pk',
            )
        self.assertEqual(self.user.pk, perm_same.pk)
        with self.assertRaises(AuthorizationPathError) as ctx:
            require_configured_operation(self.user)
        self.assertIn('operation', str(ctx.exception))
        with self.assertRaises(AuthorizationPathError):
            trust_grant_q(self.user, self.user)
