"""Delegated ``along=`` reach (#282).

A sponsor's ordinary ``along=`` grant counts in the delegation ceiling.
A delegation row may walk ``along=`` itself. When both walk, the delegate
is allowed only on objects both walks reach. Reverse inquiry agrees with
``has_perm``. One delegation level stays rejected.
"""
from contextlib import contextmanager
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.plan.relations import PlanQueryCompiler
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import RegistryFactory
from trusts.inspect.snapshot import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin
from tests.apps import render_configured_policy


def _handle(path='tests.core.issue282'):
    return RegistryFactory(path=path)

def _contribute_m2m(field, model):
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(model, field.remote_field)

def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(content_type=content_type, codename=codename, defaults={'name': codename})
    return permission

class _PairBackend(TrustModelBackendMixin, ModelBackend):
    pass

def _seal_factory(backend_cls, factory):
    from trusts.backends import catalogs
    from trusts.compile.catalogs import Catalog
    built = factory.build_registry()
    catalogs[backend_cls] = Catalog(cls=backend_cls, path='%s.%s' % (backend_cls.__module__, backend_cls.__qualname__), family=backend_cls.family, registry=built)

@contextmanager
def _listed(handle):
    from tests.apps import install_class_handle
    from trusts.backends import catalogs
    install_class_handle(_PairBackend, handle)
    _seal_factory(_PairBackend, handle)
    with override_settings(AUTHENTICATION_BACKENDS=('tests.core.test_issue282._PairBackend',)):
        try:
            yield
        finally:
            install_class_handle(_PairBackend, None)
            catalogs.pop(_PairBackend, None)

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

class Issue282SuiteRegistrationTest(SimpleTestCase):

    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue282', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue282', PAIR_KERNEL_SUITE)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class DelegatedAlongTest(TransactionTestCase):
    """Issue tree: root → child → grandchild → beyond.

    Shape S (``parent``) walks toward children. Shape C (``children``)
    walks toward parents. Depth 0 is the anchor.
    """

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        models_ = self._models()
        self.Issue, self.Grant, self.Delegation, self.GroupGrant, self.CollectionGrant = models_
        self._table_cm = _tables(*models_)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        _contribute_m2m(self.CollectionGrant._meta.get_field('permissions'), Permission)
        self.change = _permission(self.Issue, 'change_issue')
        self.add = _permission(self.Issue, 'add_issue')
        self.code = '%s.%s' % (self.change.content_type.app_label, self.change.codename)
        self.add_code = '%s.%s' % (self.add.content_type.app_label, self.add.codename)
        self.sponsor = self.User.objects.create_user('i282-sponsor', password='x')
        self.delegate = self.User.objects.create_user('i282-delegate', password='x')
        self.second = self.User.objects.create_user('i282-second', password='x')
        self.outsider = self.User.objects.create_user('i282-out', password='x')
        self.root = self.Issue.objects.create(title='root')
        self.child = self.Issue.objects.create(title='child', parent=self.root)
        self.grandchild = self.Issue.objects.create(title='grandchild', parent=self.child)
        self.beyond = self.Issue.objects.create(title='beyond', parent=self.grandchild)
        self.side = self.Issue.objects.create(title='side')

    def _models(self):

        class IssueQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Issue(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            parent = models.ForeignKey('self', null=True, related_name='children', on_delete=models.CASCADE)
            objects = models.Manager.from_queryset(IssueQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_issue'

        class Grant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            issue = models.ForeignKey(Issue, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            sponsor = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_delegation'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_group_grant'

        class CollectionGrant(models.Model):
            user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='+')
            issue = models.ForeignKey(Issue, on_delete=models.CASCADE)
            permissions = models.ManyToManyField(Permission, related_name='+', blank=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_collection_grant'
        return (Issue, Grant, Delegation, GroupGrant, CollectionGrant)

    def _register(self, *, sponsor_along=None, delegation_along=None, sponsor='permission'):
        handle = _handle()
        if sponsor == 'permission':
            handle.register_public(trust=self.Grant, user='user', permission='permission', content='issue', along=sponsor_along)
        elif sponsor == 'group':
            handle.register_public(trust=self.GroupGrant, user='group__user', group='group', content='issue', along=sponsor_along)
        elif sponsor == 'collection':
            handle.register_public(trust=self.CollectionGrant, user='user', permission='permissions', content='issue', along=sponsor_along)
        else:
            raise AssertionError(sponsor)
        handle.register_public(trust=self.Delegation, delegate='delegate', sponsor='sponsor', content='issue', along=delegation_along)
        return handle

    def _agree(self, handle, issues):
        users = (self.sponsor, self.delegate, self.second, self.outsider)
        with _listed(handle):
            for issue in issues:
                allowed = {user.pk for user in users if user.has_perm(self.code, issue)}
                found = set(issue.get_permitted_users(self.change).values_list('pk', flat=True))
                found &= {user.pk for user in users}
                self.assertEqual(found, allowed, issue.title)
                named = set(issue.get_permitted_users(self.code).values_list('pk', flat=True)) & {user.pk for user in users}
                self.assertEqual(named, allowed, issue.title)

    def test_sponsor_walk_reaches_the_delegate_on_a_child(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.child)
        handle = self._register(sponsor_along=('issue__parent', 2))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.child))
            self.assertTrue(self.sponsor.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.root))
            self.assertFalse(self.delegate.has_perm(self.code, self.beyond))
            self.assertFalse(self.delegate.has_perm(self.code, self.side))
            self.assertFalse(self.outsider.has_perm(self.code, self.child))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.child})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.child})
            self.assertIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertNotIn(self.add_code, self.delegate.get_all_permissions(self.child))
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.grandchild))
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond, self.side))
        self.Grant.objects.all().delete()
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))

    def test_delegation_walk_covers_sub_issues_the_sponsor_holds(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.grandchild, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.root)
        handle = self._register(delegation_along=('issue__parent', 3))
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.root))
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
            self.assertTrue(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.beyond))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.grandchild})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.grandchild})
            self.assertIn(self.code, self.delegate.get_all_permissions(self.grandchild))
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond))

    def test_both_walks_intersect(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.root)
        handle = self._register(sponsor_along=('issue__parent', 1), delegation_along=('issue__parent', 3))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.root))
            self.assertTrue(self.delegate.has_perm(self.code, self.child))
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.beyond))
            self.assertIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.grandchild))
            self.assertEqual(set(self.Issue.objects.permitted(self.change, self.delegate)), {self.root, self.child})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.root, self.child})
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond))

    def test_mixed_bounds_and_shapes_intersect(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.grandchild)
        handle = self._register(sponsor_along=('issue__parent', 1), delegation_along=('issue__children', 2))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.root))
            self.assertTrue(self.delegate.has_perm(self.code, self.child))
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.beyond))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.root, self.child})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.root, self.child})
            self.assertIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.grandchild))
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond))

    def test_group_sponsor_grant_walks(self):
        editors = Group.objects.create(name='i282-editors')
        editors.user_set.add(self.sponsor)
        editors.permissions.add(self.change)
        self.GroupGrant.objects.create(group=editors, issue=self.root)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.child)
        handle = self._register(sponsor='group', sponsor_along=('issue__parent', 2))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.child))
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.outsider.has_perm(self.code, self.child))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.child})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.child})
            self.assertIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.grandchild))
        editors.user_set.remove(self.sponsor)
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
        self._agree(handle, (self.root, self.child, self.grandchild))

    def test_collection_permission_sponsor_grant_walks(self):
        grant = self.CollectionGrant.objects.create(user=self.sponsor, issue=self.root)
        grant.permissions.add(self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.child)
        handle = self._register(sponsor='collection', sponsor_along=('issue__parent', 2))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.child))
            self.assertFalse(self.delegate.has_perm(self.add_code, self.child))
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))
            self.assertEqual(self.delegate.get_all_permissions(self.child), {self.code})
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.grandchild))
            self.assertFalse(self.outsider.has_perm(self.code, self.child))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.child})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.child})
        self._agree(handle, (self.root, self.child, self.grandchild))
        grant.permissions.clear()
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))

    def test_inactive_sponsor_and_delegate_keep_the_current_gate(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.child)
        handle = self._register(sponsor_along=('issue__parent', 2))
        backend = _PairBackend()
        self.sponsor.is_active = False
        self.sponsor.save(update_fields=['is_active'])
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
            self.assertFalse(backend.has_perm(self.delegate, self.code, self.child))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), set())
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), set())
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertTrue(backend.has_perm(self.delegate, self.code, self.child, skip_is_active=True))
            self.assertNotIn(self.delegate.pk, set(self.child.get_permitted_users(self.change).values_list('pk', flat=True)))
            self.assertIn(self.delegate.pk, set(self.child.get_permitted_users(self.change, skip_is_active=True).values_list('pk', flat=True)))
        self.sponsor.is_active = True
        self.sponsor.save(update_fields=['is_active'])
        self.delegate.is_active = False
        self.delegate.save(update_fields=['is_active'])
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), set())
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), set())
            self.assertNotIn(self.code, self.delegate.get_all_permissions(self.child))
            self.assertTrue(backend.has_perm(self.delegate, self.code, self.child, skip_is_active=True))
            self.assertNotIn(self.delegate.pk, set(self.child.get_permitted_users(self.change).values_list('pk', flat=True)))

    def test_delegation_chain_stays_one_level(self):
        self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.root)
        self.Delegation.objects.create(delegate=self.second, sponsor=self.delegate, issue=self.child)
        handle = self._register(sponsor_along=('issue__parent', 3), delegation_along=('issue__parent', 3))
        with _listed(handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.second.has_perm(self.code, self.child))
            self.assertFalse(self.second.has_perm(self.code, self.grandchild))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.second)), set())
            self.assertEqual(set(self.Issue.objects.authorized(self.second, self.change)), set())
            self.assertNotIn(self.code, self.second.get_all_permissions(self.grandchild))
            self.assertNotIn(self.second.pk, set(self.child.get_permitted_users(self.change).values_list('pk', flat=True)))

    def test_lockfile_records_the_walk_that_runs(self):
        handle = self._register(sponsor_along=('issue__parent', 2), delegation_along=('issue__parent', 1))
        document = _load_policy_sql_document(render_configured_policy(handle))
        self.assertEqual(document['schema_version'], 1)
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        delegation = content['delegations'][0]
        self.assertEqual(trust['along'], {'path': 'issue__parent', 'shape': 'S', 'bound': 2})
        self.assertEqual(delegation['along'], {'path': 'issue__parent', 'shape': 'S', 'bound': 1})
        self.assertIn('along_issue__parent_S_2', trust['id'])
        self.assertIn('along_issue__parent_S_1', delegation['id'])
        for operation in ('permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users'):
            row = content[operation]
            self.assertEqual(row['sql'].count('%s'), len(row['params']))
            self.assertIn('WITH RECURSIVE', row['sql'])
            bounds = [int(param.split('=', 1)[1]) for param in row['params'] if param.startswith('$along_bound=')]
            self.assertTrue(bounds, operation)
            self.assertTrue(all((value in (1, 2) for value in bounds)), operation)
            self.assertNotIn('json_', row['sql'].lower())

    def _assert_content_walk_sql(self, handle, bounds, table=None):
        document = _load_policy_sql_document(render_configured_policy(handle))
        self.assertEqual(document['schema_version'], 1)
        content = document['backends'][0]['contents'][0]
        for operation in ('permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users'):
            row = content[operation]
            self.assertEqual(row['sql'].count('%s'), len(row['params']), operation)
            self.assertIn('WITH RECURSIVE', row['sql'])
            found = [int(param.split('=', 1)[1]) for param in row['params'] if param.startswith('$along_bound=')]
            self.assertTrue(found, operation)
            self.assertTrue(all((value in bounds for value in found)), operation)
            self.assertNotIn('json_', row['sql'].lower())
            if table is not None:
                self.assertIn(table, row['sql'])
        return content

    def test_lockfile_records_each_content_walk(self):
        self._assert_content_walk_sql(self._register(sponsor_along=('issue__parent', 2)), bounds=(2,))
        self._assert_content_walk_sql(self._register(delegation_along=('issue__parent', 3)), bounds=(3,))
        self._assert_content_walk_sql(self._register(sponsor='group', sponsor_along=('issue__parent', 2)), bounds=(2,), table='issue282_group_grant')
        self._assert_content_walk_sql(self._register(sponsor='collection', sponsor_along=('issue__parent', 2)), bounds=(2,), table='issue282_collection_grant')
        self._assert_content_walk_sql(self._register(sponsor_along=('issue__parent', 1), delegation_along=('issue__children', 2)), bounds=(1, 2))
        self._assert_content_walk_sql(self._register(sponsor='group', delegation_along=('issue__parent', 3)), bounds=(3,), table='issue282_group_grant')
        self._assert_content_walk_sql(self._register(sponsor='collection', delegation_along=('issue__parent', 3)), bounds=(3,), table='issue282_collection_grant')

    def test_group_sponsor_grant_with_delegation_walk(self):
        editors = Group.objects.create(name='i282-editors-leaf')
        editors.user_set.add(self.sponsor)
        editors.permissions.add(self.change)
        self.GroupGrant.objects.create(group=editors, issue=self.grandchild)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.root)
        handle = self._register(sponsor='group', delegation_along=('issue__parent', 3))
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.root))
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
            self.assertTrue(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.code, self.beyond))
            self.assertFalse(self.outsider.has_perm(self.code, self.grandchild))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.grandchild})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.grandchild})
            self.assertEqual(self.delegate.get_all_permissions(self.grandchild), {self.code})
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond))
        editors.user_set.remove(self.sponsor)
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))

    def test_collection_permission_with_delegation_walk(self):
        grant = self.CollectionGrant.objects.create(user=self.sponsor, issue=self.grandchild)
        grant.permissions.add(self.change)
        self.Delegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.root)
        handle = self._register(sponsor='collection', delegation_along=('issue__parent', 3))
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.child))
            self.assertTrue(self.delegate.has_perm(self.code, self.grandchild))
            self.assertFalse(self.delegate.has_perm(self.add_code, self.grandchild))
            self.assertFalse(self.outsider.has_perm(self.code, self.grandchild))
            self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.grandchild})
            self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.grandchild})
            self.assertEqual(self.delegate.get_all_permissions(self.grandchild), {self.code})
        self._agree(handle, (self.root, self.child, self.grandchild, self.beyond))
        grant.permissions.clear()
        with _listed(handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.grandchild))

    def _sponsor_link_pair(self, suffix, colliding):
        user_model = self.User
        issue_model = self.Issue
        link_meta = type('Meta', (), {'app_label': 'trusts_tests', 'db_table': 'issue282_sl_%s' % suffix})
        sponsor_link = type('SponsorLink_%s' % suffix, (models.Model,), {'__module__': self.__class__.__module__, 'user': models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+'), 'Meta': link_meta})
        fields = {'__module__': self.__class__.__module__, 'delegate': models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+'), 'sponsor_link': models.ForeignKey(sponsor_link, on_delete=models.CASCADE), 'issue': models.ForeignKey(issue_model, on_delete=models.CASCADE), 'Meta': type('Meta', (), {'app_label': 'trusts_tests', 'db_table': 'issue282_ld_%s' % suffix})}
        if colliding:
            fields['user'] = models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+')
        delegation = type('LinkedDelegation_%s' % suffix, (models.Model,), fields)
        return (sponsor_link, delegation)

    def _register_linked(self, delegation):
        handle = _handle()
        handle.register_public(trust=self.Grant, user='user', permission='permission', content='issue', along=('issue__parent', 1))
        handle.register_public(trust=delegation, delegate='delegate', sponsor='sponsor_link__user', content='issue')
        return handle

    def _assert_linked_agreement(self, handle, issue, allowed):
        users = (self.sponsor, self.delegate, self.second, self.outsider)
        with _listed(handle):
            for user in users:
                self.assertEqual(user.has_perm(self.code, issue), user in allowed, user.get_username())
            found = set(issue.get_permitted_users(self.change).values_list('pk', flat=True)) & {user.pk for user in users}
            self.assertEqual(found, {user.pk for user in allowed})
            named = set(issue.get_permitted_users(self.code).values_list('pk', flat=True)) & {user.pk for user in users}
            self.assertEqual(named, {user.pk for user in allowed})

    def test_nested_sponsor_path_without_a_colliding_column(self):
        sponsor_link, delegation = self._sponsor_link_pair('plain', colliding=False)
        with _tables(sponsor_link, delegation):
            link = sponsor_link.objects.create(user=self.sponsor)
            delegation.objects.create(delegate=self.delegate, sponsor_link=link, issue=self.child)
            self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
            handle = self._register_linked(delegation)
            self._assert_linked_agreement(handle, self.child, (self.sponsor, self.delegate))
            self._assert_linked_agreement(handle, self.grandchild, ())
            with _listed(handle):
                self.assertEqual(set(self.Issue.objects.permitted(self.code, self.delegate)), {self.child})
                self.assertEqual(set(self.Issue.objects.authorized(self.delegate, self.change)), {self.child})
                self.assertIn(self.code, self.delegate.get_all_permissions(self.child))
            sql = self._assert_content_walk_sql(handle, bounds=(1,))
            self.assertIn('issue282_sl_plain', sql['has_perm']['sql'])

    def test_nested_sponsor_path_with_a_colliding_column(self):
        sponsor_link, delegation = self._sponsor_link_pair('hit', colliding=True)
        with _tables(sponsor_link, delegation):
            self.Grant.objects.create(user=self.sponsor, issue=self.root, permission=self.change)
            outsider_link = sponsor_link.objects.create(user=self.outsider)
            delegation.objects.create(delegate=self.delegate, sponsor_link=outsider_link, user=self.sponsor, issue=self.child)
            handle = self._register_linked(delegation)
            self._assert_linked_agreement(handle, self.child, (self.sponsor,))
            with _listed(handle):
                self.assertNotIn(self.child, set(self.Issue.objects.permitted(self.code, self.delegate)))
                self.assertNotIn(self.child, set(self.Issue.objects.authorized(self.delegate, self.change)))
                self.assertNotIn(self.code, self.delegate.get_all_permissions(self.child))
            holder_link = sponsor_link.objects.create(user=self.sponsor)
            delegation.objects.create(delegate=self.second, sponsor_link=holder_link, user=self.outsider, issue=self.child)
            self._assert_linked_agreement(handle, self.child, (self.sponsor, self.second))

    def test_longer_content_suffix_fails_closed(self):
        issue_model = self.Issue
        user_model = self.User

        class AttachmentQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Attachment(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            objects = models.Manager.from_queryset(AttachmentQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_attachment'

        class Note(models.Model):
            issue = models.ForeignKey(issue_model, related_name='notes', on_delete=models.CASCADE)
            attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_note'

        class AttachmentGrant(models.Model):
            user = models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+')
            attachment = models.ForeignKey(Attachment, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_attachment_grant'

        class SuffixDelegation(models.Model):
            delegate = models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+')
            sponsor = models.ForeignKey(user_model, on_delete=models.CASCADE, related_name='+')
            issue = models.ForeignKey(issue_model, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_suffix_delegation'
        change = _permission(Attachment, 'change_attachment')
        code = '%s.%s' % (change.content_type.app_label, change.codename)
        with _tables(Attachment, Note, AttachmentGrant, SuffixDelegation):
            attachment = Attachment.objects.create(title='sheet')
            Note.objects.create(issue=self.child, attachment=attachment)
            AttachmentGrant.objects.create(user=self.sponsor, attachment=attachment, permission=change)
            SuffixDelegation.objects.create(delegate=self.delegate, sponsor=self.sponsor, issue=self.child)
            handle = _handle()
            handle.register_public(trust=AttachmentGrant, user='user', permission='permission', content='attachment')
            handle.register_public(trust=SuffixDelegation, delegate='delegate', sponsor='sponsor', content='issue__notes__attachment', along=('issue__parent', 2))
            with _listed(handle):
                with self.assertRaises(TrustsConfigurationError) as raised:
                    self.delegate.has_perm(code, attachment)
                self.assertIn('notes.attachment', str(raised.exception))
                with self.assertRaises(TrustsConfigurationError):
                    self.sponsor.has_perm(code, attachment)
                for call in (lambda: set(Attachment.objects.permitted(code, self.delegate)), lambda: set(Attachment.objects.authorized(self.delegate, change)), lambda: self.delegate.get_all_permissions(attachment), lambda: set(attachment.get_permitted_users(change)), lambda: render_configured_policy(handle)):
                    with self.assertRaises(TrustsConfigurationError):
                        call()
