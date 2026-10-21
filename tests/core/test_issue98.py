"""Closed predicates and terminal membership paths (issue #98).

Public ``register(condition=...)`` plus a requester path that ends in
one membership hop. Isolated GH-shaped models use the accepted
registration spelling. No historical Trusts types required.
"""
from contextlib import contextmanager
from django.db import connection, models
from django.db.models.query import QuerySet
from django.test import TestCase, TransactionTestCase
from django.test.utils import isolate_apps
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.models import AuthorizedManager
from tests.support import listed_relationship, built_catalog, compiler


def _gh_models():
    """GH-shaped ordinary models. Nouns match the parked consumer contract."""

    class Account(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Owner(models.Model):
        """Organization stand-in; avoids tests.Organization table collision."""
        name = models.CharField(max_length=40)
        members = models.ManyToManyField(Account, related_name='organizations', blank=True)

        class Meta:
            app_label = 'trusts_tests'

    class Team(models.Model):
        organization = models.ForeignKey(Owner, related_name='teams', on_delete=models.CASCADE)
        name = models.CharField(max_length=40)
        members = models.ManyToManyField(Account, related_name='teams', blank=True)

        class Meta:
            app_label = 'trusts_tests'

    class Operation(models.Model):
        code = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class PermissionBundle(models.Model):
        team = models.ForeignKey(Team, related_name='permission_bundles', on_delete=models.CASCADE)
        name = models.CharField(max_length=40)
        operations = models.ManyToManyField(Operation, related_name='bundles', blank=True)

        class Meta:
            app_label = 'trusts_tests'

    class Repository(models.Model):
        organization = models.ForeignKey(Owner, related_name='repositories', on_delete=models.CASCADE)
        title = models.CharField(max_length=40)
        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class TeamRepoGrant(models.Model):
        team = models.ForeignKey(Team, related_name='repo_grants', on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, related_name='team_grants', on_delete=models.CASCADE)
        operation = models.ForeignKey(Operation, related_name='team_grants', on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    class AccountRepoGrant(models.Model):
        account = models.ForeignKey(Account, related_name='repo_grants', on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, related_name='direct_grants', on_delete=models.CASCADE)
        operation = models.ForeignKey(Operation, related_name='direct_grants', on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
    return (Account, Owner, Team, Operation, PermissionBundle, Repository, TeamRepoGrant, AccountRepoGrant)

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

def _register_team(registry, grant):
    """Accepted GH team spelling. Do not change this registration."""
    return registry.register(
        trust=grant,
        user=lambda t: t.team.members,
        permission=lambda t: t.operation,
        content=lambda t: t.repository,
        condition=lambda t: (
            t.team.permission_bundles.operations.contains(t.operation)
            & (t.team.organization == t.repository.organization)
        ),
    )

def _register_direct(registry, grant):
    d = Ref(grant)
    return registry.register_relation(content=d.repository, user=d.account, permission=d.operation)

def _pks(rows):
    return {row.pk for row in rows}

def _to_field_models(*, match):
    """Same target model; ``match`` shares ``to_field`` or splits slug/code."""

    class Holder(models.Model):
        name = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class Site(models.Model):
        slug = models.SlugField(unique=True)
        code = models.CharField(max_length=8, unique=True)

        class Meta:
            app_label = 'trusts_tests'

    class Document(models.Model):
        title = models.CharField(max_length=40)
        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class Action(models.Model):
        code = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'
    right_to_field = 'slug' if match else 'code'

    class SiteGrant(models.Model):
        holder = models.ForeignKey(Holder, related_name='+', on_delete=models.CASCADE)
        document = models.ForeignKey(Document, related_name='site_grants', on_delete=models.CASCADE)
        action = models.ForeignKey(Action, related_name='+', on_delete=models.CASCADE)
        left = models.ForeignKey(Site, related_name='+', on_delete=models.CASCADE, to_field='slug')
        right = models.ForeignKey(Site, related_name='+', on_delete=models.CASCADE, to_field=right_to_field)

        class Meta:
            app_label = 'trusts_tests'
    return (Holder, Site, Document, Action, SiteGrant)

def _register_site_grant(registry, grant):
    return registry.register(
        trust=grant,
        user=lambda t: t.holder,
        permission=lambda t: t.action,
        content=lambda t: t.document,
        condition=lambda t: t.left == t.right,
    )

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ClosedPredicateRegistrationTest(TestCase):

    def test_accepted_gh_team_mapping_registers_with_zero_sql(self):
        _Account, _Organization, _Team, _Operation, _Bundle, Repository, TeamRepoGrant, _Direct = _gh_models()
        registry = compiler()
        with self.assertNumQueries(0):
            record = _register_team(registry, TeamRepoGrant)
        self.assertEqual(len(registry.records), 1)
        self.assertIs(record.root, TeamRepoGrant)
        self.assertIs(record.content_model, Repository)
        self.assertEqual(record.user_path, ('team', 'members'))
        self.assertEqual(record.user_field, 'team__members')
        self.assertEqual(record.condition.kind, 'and')
        self.assertEqual(record.condition.left.kind, 'contains')
        self.assertEqual(record.condition.right.kind, 'eq')

    def test_untyped_condition_still_rejected_with_zero_sql(self):
        _models = _gh_models()
        TeamRepoGrant = _models[6]
        registry = compiler()
        with self.assertNumQueries(0):
            with self.assertRaises(TypeError):
                registry.register(
                    trust=TeamRepoGrant,
                    user=lambda t: t.team,
                    permission=lambda t: t.operation,
                    content=lambda t: t.repository,
                    condition=object(),
                )
        self.assertEqual(registry.records, ())

    def test_incompatible_equal_and_contains_paths_rejected(self):
        Account, _Organization, _Team, _Operation, _Bundle, _Repository, TeamRepoGrant, _Direct = _gh_models()
        registry = compiler()
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(TrustsConfigurationError, 'same model'):
                registry.register(
                    trust=TeamRepoGrant,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                    content=lambda t: t.repository,
                    condition=lambda t: t.team.organization == t.repository,
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'permission model'):
                registry.register(
                    trust=TeamRepoGrant,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                    content=lambda t: t.repository,
                    condition=lambda t: t.team.members.contains(t.operation),
                )
        self.assertEqual(registry.records, ())
        self.assertIs(Account._meta.concrete_model, Account)

    def test_equal_rejects_mismatched_to_field_targets_with_zero_sql(self):
        Holder, Site, Document, Action, SiteGrant = _to_field_models(match=False)
        registry = compiler()
        with self.assertNumQueries(0):
            site_a = Site(slug='acme', code='x1')
            site_b = Site(slug='other', code='acme')
            self.assertEqual(SiteGrant._meta.get_field('left').target_field.attname, 'slug')
            self.assertEqual(SiteGrant._meta.get_field('right').target_field.attname, 'code')
            self.assertEqual(site_a.slug, site_b.code)
            self.assertNotEqual(site_a.slug, site_b.slug)
            with self.assertRaisesRegex(TrustsConfigurationError, 'resolved comparison field'):
                _register_site_grant(registry, SiteGrant)
        self.assertEqual(registry.records, ())
        self.assertIs(Holder._meta.concrete_model, Holder)
        self.assertIs(Site._meta.concrete_model, Site)
        self.assertIs(Document._meta.concrete_model, Document)
        self.assertIs(Action._meta.concrete_model, Action)

    def test_equal_matching_to_field_registers_with_zero_sql(self):
        _Holder, _Site, Document, _Action, SiteGrant = _to_field_models(match=True)
        registry = compiler()
        with self.assertNumQueries(0):
            record = _register_site_grant(registry, SiteGrant)
        self.assertEqual(len(registry.records), 1)
        self.assertIs(record.content_model, Document)
        self.assertEqual(record.condition.kind, 'eq')

    def test_extra_and_intermediate_multi_valued_walks_rejected(self):
        _models = _gh_models()
        TeamRepoGrant = _models[6]
        AccountRepoGrant = _models[7]
        registry = compiler()
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(TrustsConfigurationError, 'multi-valued'):
                registry.register(
                    trust=TeamRepoGrant,
                    content=lambda t: t.team.members,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'multi-valued'):
                registry.register(
                    trust=TeamRepoGrant,
                    content=lambda t: t.repository,
                    user=lambda t: t.team.members.organizations,
                    permission=lambda t: t.operation,
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'extra or intermediate multi-valued'):
                registry.register(
                    trust=TeamRepoGrant,
                    content=lambda t: t.repository,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                    condition=lambda t: t.team.members == t.repository.organization,
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'extra or intermediate multi-valued'):
                registry.register(
                    trust=TeamRepoGrant,
                    content=lambda t: t.repository,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                    condition=lambda t: t.team.permission_bundles.operations.bundles.contains(t.operation),
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'direct single-valued'):
                registry.register(
                    trust=AccountRepoGrant,
                    content=lambda t: t.repository,
                    user=lambda t: t.repository.organization,
                    permission=lambda t: t.operation,
                )
            with self.assertRaisesRegex(TrustsConfigurationError, 'multi-valued|reverse'):
                registry.register(
                    trust=AccountRepoGrant,
                    content=lambda t: t.repository,
                    user=lambda t: t.account.repo_grants.repository,
                    permission=lambda t: t.operation,
                )
        self.assertEqual(registry.records, ())

    def test_mixed_root_predicate_refs_rejected(self):
        _models = _gh_models()
        TeamRepoGrant = _models[6]
        AccountRepoGrant = _models[7]
        registry = compiler()
        other = Ref(AccountRepoGrant)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(TrustsConfigurationError, 'constant'):
                registry.register(
                    trust=TeamRepoGrant,
                    user=lambda t: t.team.members,
                    permission=lambda t: t.operation,
                    content=lambda t: t.repository,
                    condition=lambda t: t.team.organization == other.repository.organization,
                )
        self.assertEqual(registry.records, ())

    def test_direct_user_hop_still_registers(self):
        _models = _gh_models()
        AccountRepoGrant = _models[7]
        registry = compiler()
        with self.assertNumQueries(0):
            record = _register_direct(registry, AccountRepoGrant)
        self.assertEqual(record.user_path, ('account',))
        self.assertIsNone(record.condition)

    def test_condition_none_still_accepted(self):
        _models = _gh_models()
        AccountRepoGrant = _models[7]
        registry = compiler()
        d = Ref(AccountRepoGrant)
        record = registry.register_relation(content=d.repository, user=d.account, permission=d.operation, condition=None)
        self.assertIsNone(record.condition)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ClosedPredicateAuthorizationTest(TransactionTestCase):

    def setUp(self):
        self.Account, self.Organization, self.Team, self.Operation, self.PermissionBundle, self.Repository, self.TeamRepoGrant, self.AccountRepoGrant = _gh_models()
        self._table_cm = _tables(self.Account, self.Organization, self.Team, self.Operation, self.PermissionBundle, self.Repository, self.TeamRepoGrant, self.AccountRepoGrant)
        self._table_cm.__enter__()
        self.org_a = self.Organization.objects.create(name='acme')
        self.org_b = self.Organization.objects.create(name='other')
        self.writers = self.Team.objects.create(organization=self.org_a, name='writers')
        self.outsiders = self.Team.objects.create(organization=self.org_b, name='outsiders')
        self.member = self.Account.objects.create(name='member')
        self.collaborator = self.Account.objects.create(name='collaborator')
        self.org_only = self.Account.objects.create(name='org-only')
        self.stranger = self.Account.objects.create(name='stranger')
        self.org_a.members.add(self.member, self.org_only)
        self.org_b.members.add(self.stranger)
        self.writers.members.add(self.member)
        self.read = self.Operation.objects.create(code='read')
        self.write = self.Operation.objects.create(code='write')
        self.bundle = self.PermissionBundle.objects.create(team=self.writers, name='reader')
        self.bundle.operations.add(self.read)
        self.repo_a = self.Repository.objects.create(organization=self.org_a, title='repo-a')
        self.repo_b = self.Repository.objects.create(organization=self.org_a, title='repo-b')
        self.repo_other = self.Repository.objects.create(organization=self.org_b, title='repo-other')
        self.TeamRepoGrant.objects.create(team=self.writers, repository=self.repo_a, operation=self.read)
        self.AccountRepoGrant.objects.create(account=self.collaborator, repository=self.repo_b, operation=self.write)
        self.registry = compiler()
        _register_direct(self.registry, self.AccountRepoGrant)
        _register_team(self.registry, self.TeamRepoGrant)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def _handles(self):
        self.registry.path = 'issue98'
        return (self.registry,)

    def _object_list_agree(self, principal, operation, obj, expected):
        with self.assertNumQueries(1):
            via_obj = built_catalog(self.registry).has_permission(principal, obj, operation)
        with self.assertNumQueries(1):
            via_list = obj in list(built_catalog(self.registry).filter_authorized(self.Repository.objects.filter(pk=obj.pk), principal, operation))
        with listed_relationship(self._handles()):
            with self.assertNumQueries(1):
                via_manager = obj in list(self.Repository.objects.filter(pk=obj.pk).authorized(principal, operation))
            with self.assertNumQueries(1):
                via_exists = self.Repository.objects.filter(pk=obj.pk).authorized(principal, operation).exists()
        enumerated = {row.pk for row in built_catalog(self.registry).permissions_for(principal, obj)}
        self.assertEqual(via_obj, expected)
        self.assertEqual(via_list, expected)
        self.assertEqual(via_manager, expected)
        self.assertEqual(via_exists, expected)
        if expected:
            self.assertIn(operation.pk, enumerated)
        else:
            self.assertNotIn(operation.pk, enumerated)

    def test_team_member_grant_bundle_and_same_org_allows(self):
        self._object_list_agree(self.member, self.read, self.repo_a, True)
        self._object_list_agree(self.member, self.write, self.repo_a, False)
        self._object_list_agree(self.member, self.read, self.repo_b, False)

    def test_removing_membership_denies_only_that_branch(self):
        self.writers.members.remove(self.member)
        self._object_list_agree(self.member, self.read, self.repo_a, False)
        self._object_list_agree(self.collaborator, self.write, self.repo_b, True)

    def test_removing_team_grant_denies_only_that_branch(self):
        self.TeamRepoGrant.objects.filter(team=self.writers, repository=self.repo_a, operation=self.read).delete()
        self._object_list_agree(self.member, self.read, self.repo_a, False)
        self._object_list_agree(self.collaborator, self.write, self.repo_b, True)

    def test_removing_bundle_operation_denies_only_that_branch(self):
        self.bundle.operations.remove(self.read)
        self._object_list_agree(self.member, self.read, self.repo_a, False)
        self._object_list_agree(self.collaborator, self.write, self.repo_b, True)

    def test_removing_organization_alignment_denies_only_that_branch(self):
        self.writers.organization = self.org_b
        self.writers.save()
        self._object_list_agree(self.member, self.read, self.repo_a, False)
        self._object_list_agree(self.collaborator, self.write, self.repo_b, True)

    def test_cross_organization_team_grant_denies(self):
        self.TeamRepoGrant.objects.create(team=self.writers, repository=self.repo_other, operation=self.read)
        self._object_list_agree(self.member, self.read, self.repo_other, False)

    def test_direct_and_team_roots_or_compose(self):
        self.AccountRepoGrant.objects.create(account=self.member, repository=self.repo_b, operation=self.read)
        self._object_list_agree(self.member, self.read, self.repo_a, True)
        self._object_list_agree(self.member, self.read, self.repo_b, True)
        self.TeamRepoGrant.objects.filter(team=self.writers, repository=self.repo_a, operation=self.read).delete()
        self._object_list_agree(self.member, self.read, self.repo_a, False)
        self._object_list_agree(self.member, self.read, self.repo_b, True)

    def test_membership_or_attachment_alone_grants_nothing(self):
        self._object_list_agree(self.org_only, self.read, self.repo_a, False)
        self._object_list_agree(self.stranger, self.read, self.repo_other, False)
        self.outsiders.members.add(self.stranger)
        self._object_list_agree(self.stranger, self.read, self.repo_other, False)

    def test_query_construction_is_lazy_and_fixed_count(self):
        with self.assertNumQueries(0):
            qs = built_catalog(self.registry).filter_authorized(self.Repository.objects.all(), self.member, self.read)
            enumerated = built_catalog(self.registry).permissions_for(self.member, self.repo_a)
        self.assertIsInstance(qs, QuerySet)
        self.assertIsInstance(enumerated, QuerySet)
        self.assertIsNone(qs._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs), {self.repo_a.pk})
        page = built_catalog(self.registry).filter_authorized(self.Repository.objects.order_by('pk'), self.member, self.read)[:1]
        with self.assertNumQueries(1):
            self.assertEqual(list(page), [self.repo_a])
        sql = str(built_catalog(self.registry).filter_authorized(self.Repository.objects.all(), self.member, self.read).query).lower().replace('_', '').replace('"', '')
        self.assertIn('exists', sql)
        self.assertIn('teamrepogrant', sql)

    def test_unregistered_content_fails_closed(self):
        empty = compiler()
        self.assertFalse(built_catalog(empty).has_permission(self.member, self.repo_a, self.read))
        missing = built_catalog(empty).filter_authorized(self.Repository.objects.all(), self.member, self.read)
        self.assertEqual(list(missing), [])
        self.assertEqual(list(built_catalog(empty).permissions_for(self.member, self.repo_a)), [])

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ClosedPredicateEqualToFieldAuthorizationTest(TransactionTestCase):

    def setUp(self):
        self.Holder, self.Site, self.Document, self.Action, self.SiteGrant = _to_field_models(match=True)
        self._table_cm = _tables(self.Holder, self.Site, self.Document, self.Action, self.SiteGrant)
        self._table_cm.__enter__()
        self.holder = self.Holder.objects.create(name='holder')
        self.site_a = self.Site.objects.create(slug='alpha', code='a1')
        self.site_b = self.Site.objects.create(slug='beta', code='b2')
        self.read = self.Action.objects.create(code='read')
        self.doc_same = self.Document.objects.create(title='aligned')
        self.doc_other = self.Document.objects.create(title='split')
        self.SiteGrant.objects.create(holder=self.holder, document=self.doc_same, action=self.read, left=self.site_a, right=self.site_a)
        self.SiteGrant.objects.create(holder=self.holder, document=self.doc_other, action=self.read, left=self.site_a, right=self.site_b)
        self.registry = compiler()
        _register_site_grant(self.registry, self.SiteGrant)

    def tearDown(self):
        self._table_cm.__exit__(None, None, None)

    def test_matching_to_field_same_object_allows_and_split_denies(self):
        with self.assertNumQueries(1):
            self.assertTrue(built_catalog(self.registry).has_permission(self.holder, self.doc_same, self.read))
        with self.assertNumQueries(1):
            self.assertFalse(built_catalog(self.registry).has_permission(self.holder, self.doc_other, self.read))
        with self.assertNumQueries(1):
            self.assertEqual(_pks(built_catalog(self.registry).filter_authorized(self.Document.objects.all(), self.holder, self.read)), {self.doc_same.pk})
