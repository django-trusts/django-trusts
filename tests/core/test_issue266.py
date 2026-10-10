"""Delegated authority registration and one-level correlated grants (#266)."""

from contextlib import contextmanager

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import isolate_apps, override_settings

from tests.core import kernel_host_listed
from tests.myapp.models import Document, DocumentDelegation, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.backends import TrustModelBackendMixin
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    RegisteredDelegation,
    TrustsConfigurationError,
    TrustsRegistry,
    _compile_common_permissions,
    _compile_granted,
)
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts._permitted import permitted_queryset
from trusts.query import PermittedManager, PermittedQuerySet, PermittedUsersMixin
from trusts.reverse import lock_permitted_users_queryset


def _handle(path='tests.core.issue266'):
    return BackendHandle(
        path=path,
        registry=TrustsRegistry(),
        compiler=PlanQueryCompiler(),
    )


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


class _PairDocumentBackend(TrustModelBackendMixin, ModelBackend):
    """Stand-in for ``DocumentBackend`` when pair settings omit myapp."""

    handle = None

    def _own_handle(self):
        handle = type(self).handle
        if handle is None:
            raise TrustsConfigurationError('pair document handle is unset')
        return handle


def _document_host_handle():
    """Same registration ``DocumentConfig.ready`` installs on the kernel host."""
    handle = _handle('tests.myapp.backends.DocumentBackend')
    handle.register(
        trust=DocumentGrant,
        user='user',
        permission='permission',
        content='document',
    )
    handle.register(
        trust=DocumentDelegation,
        delegate='delegate',
        sponsor='sponsor',
        content='document',
        condition=lambda relationship, permission: (
            relationship.allowed_permissions.contains(permission)
        ),
    )
    handle.add_named_filter(
        Document,
        'non_confidential',
        lambda user, permission, obj: obj.confidential != True,
    )
    return handle


@contextmanager
def _listed(handle):
    _PairDocumentBackend.handle = handle
    with override_settings(AUTHENTICATION_BACKENDS=(
        'tests.core.test_issue266._PairDocumentBackend',
    )), patch(
        'trusts.apps._relationship_implementation_handles',
        return_value=(handle,),
    ):
        try:
            yield
        finally:
            _PairDocumentBackend.handle = None


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


def _indirect_content_models():
    class Principal(PermissionsMixin, models.Model):
        username = models.CharField(max_length=80, unique=True)
        is_active = models.BooleanField(default=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_principal'

    class PersonalOrganization(models.Model):
        personal_user = models.OneToOneField(
            Principal,
            related_name='personal_organization_issue266_query',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_personal_organization'

    class Repository(PermittedUsersMixin, models.Model):
        organization = models.ForeignKey(
            PersonalOrganization,
            related_name='repositories',
            on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=80)

        objects = PermittedManager()

        def get_permitted_users(self, perm):
            from trusts.reverse import compile_permitted_users

            return compile_permitted_users(
                self, perm,
                user_queryset=Principal.objects.all(),
            )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_repository'

    class DirectGrant(models.Model):
        user = models.ForeignKey(Principal, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_direct_grant'

    class AllPersonalDelegation(models.Model):
        delegate = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        sponsor = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        allowed_permissions = models.ManyToManyField(Permission)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_all_personal_delegation'

    return (
        Principal, PersonalOrganization, Repository, DirectGrant,
        AllPersonalDelegation,
    )


def _contribute_m2m(field, model):
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(model, field.remote_field)


class DelegationSuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue266', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue266', PAIR_KERNEL_SUITE)


class DelegationRegistrationTest(TestCase):
    def test_two_argument_condition_records_permission_scope(self):
        calls = []

        def condition(relationship, permission):
            calls.append((relationship, permission))
            return relationship.allowed_permissions.contains(permission)

        handle = _handle()
        with self.assertNumQueries(0):
            record = handle.register(
                trust=DocumentDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='document',
                condition=condition,
            )
        self.assertIsInstance(record, RegisteredDelegation)
        self.assertEqual(len(calls), 1)
        self.assertEqual(record.delegate_field, 'delegate')
        self.assertEqual(record.sponsor_field, 'sponsor')
        self.assertEqual(record.content_field, 'document')
        self.assertIs(record.condition_permission_model, Permission)
        self.assertEqual(handle.registry.records, ())
        self.assertEqual(handle.registry.delegations, (record,))

    def test_one_argument_condition_is_row_only(self):
        handle = _handle()
        record = handle.register(
            trust=DocumentDelegation,
            delegate=lambda d: d.delegate,
            sponsor=lambda d: d.sponsor,
            content=lambda d: d.document,
            condition=lambda d: d.delegate == d.sponsor,
        )
        self.assertIsNone(record.condition_permission_model)

    @isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
    def test_content_may_cross_reverse_one_to_one_before_gateway(self):
        class Principal(models.Model):
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'

        class PersonalOrganization(models.Model):
            personal_user = models.OneToOneField(
                Principal,
                related_name='personal_organization_issue266',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Repository(models.Model):
            organization = models.ForeignKey(
                PersonalOrganization,
                related_name='repositories',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class PersonalDelegation(models.Model):
            delegate = models.ForeignKey(
                Principal, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                Principal, related_name='+', on_delete=models.CASCADE,
            )
            allowed_permissions = models.ManyToManyField(Permission)

            class Meta:
                app_label = 'trusts_tests'

        handle = _handle()
        with self.assertNumQueries(0):
            record = handle.register(
                trust=PersonalDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content=(
                    'sponsor__personal_organization_issue266__repositories'
                ),
                condition=lambda relationship, permission: (
                    relationship.allowed_permissions.contains(permission)
                ),
            )

        self.assertEqual(
            record.content_path,
            (
                'sponsor', 'personal_organization_issue266',
                'repositories',
            ),
        )
        self.assertIs(record.content_model, Repository)
        self.assertEqual(
            record.content_field,
            'sponsor__personal_organization_issue266__repositories',
        )

    def test_incomplete_and_crossed_modes_fail_before_builder_invocation(self):
        cases = (
            {'delegate': 'delegate'},
            {'sponsor': 'sponsor'},
            {
                'user': 'delegate', 'permission': 'allowed_permissions',
                'delegate': 'delegate', 'sponsor': 'sponsor',
            },
            {},
        )
        for extra in cases:
            calls = []
            with self.subTest(extra=extra):
                handle = _handle()
                with self.assertNumQueries(0):
                    with self.assertRaises(TrustsConfigurationError):
                        handle.register(
                            trust=DocumentDelegation,
                            content='document',
                            condition=lambda *args: calls.append(args),
                            **extra,
                        )
                self.assertEqual(calls, [])
                self.assertEqual(handle.registry.records, ())
                self.assertEqual(handle.registry.delegations, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ReverseOneToOneDelegationQueryTest(TransactionTestCase):
    def setUp(self):
        (
            self.Principal,
            self.PersonalOrganization,
            self.Repository,
            self.DirectGrant,
            self.AllPersonalDelegation,
        ) = _indirect_content_models()
        self._table_cm = _tables(
            self.Principal,
            self.PersonalOrganization,
            self.Repository,
            self.DirectGrant,
            self.AllPersonalDelegation,
        )
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        _contribute_m2m(
            self.AllPersonalDelegation._meta.get_field(
                'allowed_permissions'
            ),
            Permission,
        )

        self.sponsor = self.Principal.objects.create(
            username='indirect-sponsor-266',
        )
        self.delegate = self.Principal.objects.create(
            username='indirect-delegate-266',
        )
        self.sponsor_without_personal_org = self.Principal.objects.create(
            username='indirect-sponsor-without-org-266',
        )
        self.delegate_without_personal_org = self.Principal.objects.create(
            username='indirect-delegate-without-org-266',
        )
        self.read = _permission(self.Repository, 'read_repository')
        self.code = '%s.%s' % (
            self.read.content_type.app_label, self.read.codename,
        )
        organization = self.PersonalOrganization.objects.create(
            personal_user=self.sponsor,
        )
        self.repository = self.Repository.objects.create(
            organization=organization, title='indirect-repository-266',
        )
        for sponsor in (
            self.sponsor, self.sponsor_without_personal_org,
        ):
            self.DirectGrant.objects.create(
                user=sponsor,
                repository=self.repository,
                permission=self.read,
            )
        for delegate, sponsor in (
            (self.delegate, self.sponsor),
            (
                self.delegate_without_personal_org,
                self.sponsor_without_personal_org,
            ),
        ):
            relationship = self.AllPersonalDelegation.objects.create(
                delegate=delegate, sponsor=sponsor,
            )
            relationship.allowed_permissions.add(self.read)

        self.handle = _handle('tests.core.issue266.indirect')
        self.handle.register(
            trust=self.DirectGrant,
            user='user',
            permission='permission',
            content='repository',
        )
        self.handle.register(
            trust=self.AllPersonalDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content=(
                'sponsor__personal_organization_issue266_query'
                '__repositories'
            ),
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )

    def tearDown(self):
        ContentType.objects.clear_cache()
        super().tearDown()

    def test_reverse_one_to_one_prefix_agrees_across_query_surfaces(self):
        with _listed(self.handle):
            self.assertTrue(
                self.delegate.has_perm(self.code, self.repository)
            )
            self.assertEqual(
                list(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                [self.repository],
            )
            self.assertIn(
                self.delegate,
                set(self.repository.get_permitted_users(self.read)),
            )

            # This sponsor has a live ordinary grant and a delegation row,
            # but no reverse one-to-one personal organization. Every public
            # query surface denies cleanly rather than raising.
            self.assertTrue(
                self.sponsor_without_personal_org.has_perm(
                    self.code, self.repository,
                )
            )
            self.assertFalse(
                self.delegate_without_personal_org.has_perm(
                    self.code, self.repository,
                )
            )
            self.assertEqual(
                list(self.Repository.objects.permitted(
                    self.read, self.delegate_without_personal_org,
                )),
                [],
            )
            self.assertNotIn(
                self.delegate_without_personal_org,
                set(self.repository.get_permitted_users(self.read)),
            )

    def test_another_organization_stays_denied_with_a_sponsor_grant(self):
        other = self.Principal.objects.create(username='indirect-other-266')
        foreign_org = self.PersonalOrganization.objects.create(
            personal_user=other,
        )
        foreign = self.Repository.objects.create(
            organization=foreign_org, title='indirect-foreign-266',
        )
        self.DirectGrant.objects.create(
            user=self.sponsor, repository=foreign, permission=self.read,
        )
        sibling = self.Repository.objects.create(
            organization=self.repository.organization,
            title='indirect-sibling-266',
        )
        with _listed(self.handle):
            self.assertTrue(self.sponsor.has_perm(self.code, foreign))
            self.assertFalse(self.delegate.has_perm(self.code, foreign))
            self.assertNotIn(
                foreign,
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
            )
            self.assertFalse(self.delegate.has_perm(self.code, sibling))
            self.DirectGrant.objects.create(
                user=self.sponsor, repository=sibling, permission=self.read,
            )
            self.assertEqual(
                self.AllPersonalDelegation.objects.filter(
                    delegate=self.delegate, sponsor=self.sponsor,
                ).count(),
                1,
            )
            self.assertTrue(self.delegate.has_perm(self.code, sibling))
            self.assertIn(
                sibling,
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
            )

    def test_revoking_the_sponsor_grant_denies_the_delegate(self):
        self.DirectGrant.objects.filter(user=self.sponsor).delete()
        self.assertTrue(
            self.AllPersonalDelegation.objects.filter(
                delegate=self.delegate, sponsor=self.sponsor,
            ).exists()
        )
        with _listed(self.handle):
            self.assertFalse(
                self.delegate.has_perm(self.code, self.repository)
            )
            self.assertEqual(
                list(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                [],
            )
            self.assertNotIn(
                self.delegate,
                set(self.repository.get_permitted_users(self.read)),
            )

    def test_enumeration_and_policy_lock_agree(self):
        with _listed(self.handle):
            self.assertIn(
                self.code,
                self.delegate.get_all_permissions(self.repository),
            )
            self.assertNotIn(
                self.code,
                self.delegate_without_personal_org.get_all_permissions(
                    self.repository,
                ),
            )
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        content = document['backends'][0]['contents'][0]
        delegation = content['delegations'][0]
        self.assertEqual(
            delegation['content']['path'],
            'sponsor__personal_organization_issue266_query__repositories',
        )
        self.assertIs(delegation['or_group'], True)
        self.assertEqual(delegation['delegate']['path'], 'delegate')
        self.assertEqual(delegation['sponsor']['path'], 'sponsor')
        for operation in (
            'permitted', 'has_perm', 'get_all_permissions',
            'get_permitted_users',
        ):
            sql = content[operation]['sql']
            self.assertEqual(
                sql.count('"issue266_all_personal_delegation"'), 1,
            )
            self.assertIn('issue266_personal_organization', sql)
            self.assertIn('issue266_direct_grant', sql)


def _approved_condition(relationship, permission):
    """This root's approver plus its own permission list."""
    return (relationship.approver == relationship.sponsor) & (
        relationship.allowed_permissions.contains(permission)
    )


def _two_prefix_models():
    """Two reverse one-to-one hops, then one repository gateway."""

    class Principal(PermissionsMixin, models.Model):
        username = models.CharField(max_length=80, unique=True)
        is_active = models.BooleanField(default=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_principal'

    class PersonalProfile(models.Model):
        user = models.OneToOneField(
            Principal, related_name='personal_profile_two',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_profile'

    class PersonalOrganization(models.Model):
        profile = models.OneToOneField(
            PersonalProfile, related_name='personal_organization_two',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_organization'

    class Repository(PermittedUsersMixin, models.Model):
        organization = models.ForeignKey(
            PersonalOrganization, related_name='repositories',
            on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=80)
        objects = PermittedManager()

        def get_permitted_users(self, perm):
            from trusts.reverse import compile_permitted_users

            return compile_permitted_users(
                self, perm, user_queryset=Principal.objects.all(),
            )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_repository'

    class DirectGrant(models.Model):
        user = models.ForeignKey(Principal, on_delete=models.CASCADE)
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_direct_grant'

    class Note(models.Model):
        title = models.CharField(max_length=80)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_note'

    class NoteGrant(models.Model):
        """Ordinary root for a different content model."""

        user = models.ForeignKey(Principal, on_delete=models.CASCADE)
        note = models.ForeignKey(Note, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_note_grant'

    class PersonalDelegation(models.Model):
        delegate = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        sponsor = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_personal_delegation'

    class ApprovedDelegation(models.Model):
        repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        sponsor = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        approver = models.ForeignKey(
            Principal, related_name='+', on_delete=models.CASCADE,
        )
        allowed_permissions = models.ManyToManyField(Permission)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_two_approved_delegation'

    return (
        Principal, PersonalProfile, PersonalOrganization, Repository,
        DirectGrant, Note, NoteGrant, PersonalDelegation, ApprovedDelegation,
    )


_TWO_PREFIX = (
    'sponsor__personal_profile_two__personal_organization_two__repositories'
)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TwoRootDelegationTest(TransactionTestCase):
    """Two delegation roots on Repository, one of them a two-prefix chain."""

    def setUp(self):
        (
            self.Principal,
            self.PersonalProfile,
            self.PersonalOrganization,
            self.Repository,
            self.DirectGrant,
            self.Note,
            self.NoteGrant,
            self.PersonalDelegation,
            self.ApprovedDelegation,
        ) = _two_prefix_models()
        self._table_cm = _tables(
            self.Principal,
            self.PersonalProfile,
            self.PersonalOrganization,
            self.Repository,
            self.DirectGrant,
            self.PersonalDelegation,
            self.ApprovedDelegation,
        )
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        _contribute_m2m(
            self.ApprovedDelegation._meta.get_field('allowed_permissions'),
            Permission,
        )
        self.sponsor = self.Principal.objects.create(username='two-sponsor')
        self.delegate = self.Principal.objects.create(username='two-delegate')
        self.second = self.Principal.objects.create(username='two-second')
        self.other = self.Principal.objects.create(username='two-other')
        self.read = _permission(self.Repository, 'read_repository')
        self.delete = _permission(self.Repository, 'delete_repository')
        self.code = '%s.%s' % (
            self.read.content_type.app_label, self.read.codename,
        )
        self.delete_code = '%s.%s' % (
            self.delete.content_type.app_label, self.delete.codename,
        )
        profile = self.PersonalProfile.objects.create(user=self.sponsor)
        organization = self.PersonalOrganization.objects.create(
            profile=profile,
        )
        self.own = self.Repository.objects.create(
            organization=organization, title='two-own',
        )
        self.sibling = self.Repository.objects.create(
            organization=organization, title='two-sibling',
        )
        other_profile = self.PersonalProfile.objects.create(user=self.other)
        other_org = self.PersonalOrganization.objects.create(
            profile=other_profile,
        )
        self.foreign = self.Repository.objects.create(
            organization=other_org, title='two-foreign',
        )
        self.DirectGrant.objects.create(
            user=self.sponsor, repository=self.own, permission=self.read,
        )
        self.DirectGrant.objects.create(
            user=self.sponsor, repository=self.foreign, permission=self.read,
        )
        self.PersonalDelegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor,
        )
        self.handle = _handle('tests.core.issue266.two-roots')
        self.handle.register(
            trust=self.NoteGrant,
            user='user',
            permission='permission',
            content='note',
        )
        self.handle.register(
            trust=self.DirectGrant,
            user='user',
            permission='permission',
            content='repository',
        )
        self.personal = self.handle.register(
            trust=self.PersonalDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content=_TWO_PREFIX,
        )
        self.approved = self.handle.register(
            trust=self.ApprovedDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='repository',
            condition=_approved_condition,
        )

    def tearDown(self):
        ContentType.objects.clear_cache()
        super().tearDown()

    def _approved_row(self, repository, delegate, sponsor, approver):
        row = self.ApprovedDelegation.objects.create(
            repository=repository,
            delegate=delegate,
            sponsor=sponsor,
            approver=approver,
        )
        row.allowed_permissions.add(self.read)
        return row

    def test_two_prefix_chain_covers_that_org_only(self):
        self.assertEqual(
            self.personal.content_path,
            (
                'sponsor', 'personal_profile_two',
                'personal_organization_two', 'repositories',
            ),
        )
        self.assertIs(self.personal.content_model, self.Repository)
        self.assertIsNone(self.personal.condition)
        roots = [
            record.root for record in self.handle.registry.delegations
        ]
        self.assertEqual(
            roots, [self.PersonalDelegation, self.ApprovedDelegation],
        )
        with _listed(self.handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.own))
            self.assertFalse(self.delegate.has_perm(self.code, self.sibling))
            self.assertFalse(self.delegate.has_perm(self.code, self.foreign))
            self.assertTrue(self.sponsor.has_perm(self.code, self.foreign))
            self.assertFalse(
                self.delegate.has_perm(self.delete_code, self.own)
            )
            self.assertEqual(
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                {self.own},
            )
            self.DirectGrant.objects.create(
                user=self.sponsor, repository=self.sibling,
                permission=self.read,
            )
            self.assertEqual(self.PersonalDelegation.objects.count(), 1)
            self.assertEqual(
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                {self.own, self.sibling},
            )
            self.assertNotIn(
                self.foreign,
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
            )

    def test_approval_root_stays_isolated_from_the_personal_root(self):
        self._approved_row(
            self.foreign, self.delegate, self.sponsor, self.other,
        )
        with _listed(self.handle):
            self.assertFalse(
                self.delegate.has_perm(self.code, self.foreign)
            )
            self.assertTrue(self.delegate.has_perm(self.code, self.own))
        self.ApprovedDelegation.objects.update(approver=self.sponsor)
        with _listed(self.handle):
            self.assertTrue(self.delegate.has_perm(self.code, self.foreign))
            self.assertIn(
                self.foreign,
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
            )
        self.PersonalDelegation.objects.all().delete()
        with _listed(self.handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.own))
            self.assertTrue(self.delegate.has_perm(self.code, self.foreign))
            self.assertEqual(
                set(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                {self.foreign},
            )

    def test_revoking_the_sponsor_denies_both_roots(self):
        self._approved_row(
            self.foreign, self.delegate, self.sponsor, self.sponsor,
        )
        self.DirectGrant.objects.filter(user=self.sponsor).delete()
        self.assertEqual(self.PersonalDelegation.objects.count(), 1)
        self.assertEqual(self.ApprovedDelegation.objects.count(), 1)
        with _listed(self.handle):
            self.assertFalse(self.delegate.has_perm(self.code, self.own))
            self.assertFalse(self.delegate.has_perm(self.code, self.foreign))
            self.assertEqual(
                list(self.Repository.objects.permitted(
                    self.read, self.delegate,
                )),
                [],
            )
            self.assertNotIn(
                self.delegate, set(self.own.get_permitted_users(self.read)),
            )
            self.assertNotIn(
                self.delegate,
                set(self.foreign.get_permitted_users(self.read)),
            )

    def test_neither_root_can_sponsor_another_delegation(self):
        profile = self.PersonalProfile.objects.create(user=self.delegate)
        organization = self.PersonalOrganization.objects.create(
            profile=profile,
        )
        delegate_repo = self.Repository.objects.create(
            organization=organization, title='two-delegate-repo',
        )
        self.DirectGrant.objects.create(
            user=self.sponsor, repository=delegate_repo, permission=self.read,
        )
        self._approved_row(
            delegate_repo, self.delegate, self.sponsor, self.sponsor,
        )
        self.PersonalDelegation.objects.create(
            delegate=self.second, sponsor=self.delegate,
        )
        self._approved_row(
            self.own, self.second, self.delegate, self.delegate,
        )
        with _listed(self.handle):
            self.assertTrue(
                self.delegate.has_perm(self.code, delegate_repo)
            )
            self.assertTrue(self.delegate.has_perm(self.code, self.own))
            self.assertFalse(self.second.has_perm(self.code, delegate_repo))
            self.assertFalse(self.second.has_perm(self.code, self.own))
            self.assertNotIn(
                self.second,
                set(delegate_repo.get_permitted_users(self.read)),
            )

    def test_unrelated_ordinary_root_does_not_grant(self):
        lone = _handle('tests.core.issue266.unrelated')
        lone.register(
            trust=self.NoteGrant,
            user='user',
            permission='permission',
            content='note',
        )
        lone.register(
            trust=self.PersonalDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content=_TWO_PREFIX,
        )
        with _listed(lone):
            self.assertFalse(self.delegate.has_perm(self.code, self.own))
            with self.assertRaisesRegex(
                TrustsConfigurationError,
                'no applicable auth.Permission plan',
            ):
                self.Repository.objects.permitted(self.read, self.delegate)
            self.assertNotIn(
                self.delegate, set(self.own.get_permitted_users(self.read)),
            )

    def test_enumeration_and_policy_lock_have_one_branch_per_root(self):
        self._approved_row(
            self.foreign, self.delegate, self.sponsor, self.sponsor,
        )
        with _listed(self.handle):
            self.assertIn(
                self.code, self.delegate.get_all_permissions(self.own),
            )
            self.assertIn(
                self.code, self.delegate.get_all_permissions(self.foreign),
            )
            self.assertNotIn(
                self.code, self.delegate.get_all_permissions(self.sibling),
            )
            self.assertEqual(
                set(self.own.get_permitted_users(self.read)),
                {self.sponsor, self.delegate},
            )
            self.assertIn(
                self.delegate,
                set(self.foreign.get_permitted_users(self.read)),
            )
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        by_model = {
            row['model']: row
            for row in document['backends'][0]['contents']
        }
        content = by_model[self.Repository._meta.label]
        delegations = content['delegations']
        self.assertEqual(
            [row['root'] for row in delegations],
            [
                self.PersonalDelegation._meta.label,
                self.ApprovedDelegation._meta.label,
            ],
        )
        self.assertEqual(delegations[0]['content']['path'], _TWO_PREFIX)
        self.assertEqual(delegations[1]['content']['path'], 'repository')
        for row in delegations:
            self.assertIs(row['or_group'], True)
        for operation in (
            'permitted', 'has_perm', 'get_all_permissions',
            'get_permitted_users',
        ):
            sql = content[operation]['sql']
            self.assertEqual(
                sql.count('"issue266_two_personal_delegation"'), 1,
            )
            self.assertEqual(
                sql.count('"issue266_two_approved_delegation"'), 1,
            )
            self.assertEqual(sql.count('approver_id'), 1)
            self.assertIn('issue266_two_profile', sql)
            self.assertIn('issue266_two_organization', sql)
            self.assertIn('issue266_two_direct_grant', sql)
        self.assertNotIn('delegations', by_model[self.Note._meta.label])


def _ordinary_prefix_models():
    class Principal(PermissionsMixin, models.Model):
        username = models.CharField(max_length=80, unique=True)
        is_active = models.BooleanField(default=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_ord_principal'

    class Profile(models.Model):
        holder = models.ForeignKey(Principal, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_ord_profile'

    class PersonalOrganization(models.Model):
        profile = models.OneToOneField(
            Profile, related_name='personal_organization_ord',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_ord_organization'

    class Repository(PermittedUsersMixin, models.Model):
        organization = models.ForeignKey(
            PersonalOrganization, related_name='repositories',
            on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=80)
        objects = PermittedManager()

        def get_permitted_users(self, perm):
            from trusts.reverse import compile_permitted_users

            return compile_permitted_users(
                self, perm, user_queryset=Principal.objects.all(),
            )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_ord_repository'

    class ProfileGrant(models.Model):
        user = models.ForeignKey(Principal, on_delete=models.CASCADE)
        profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue266_ord_profile_grant'

    return (
        Principal, Profile, PersonalOrganization, Repository, ProfileGrant,
    )


_ORDINARY_PREFIX = 'profile__personal_organization_ord__repositories'


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class OrdinaryReverseOneToOneGrantTest(TransactionTestCase):
    """Ordinary registration through one reverse one-to-one prefix."""

    def setUp(self):
        (
            self.Principal,
            self.Profile,
            self.PersonalOrganization,
            self.Repository,
            self.ProfileGrant,
        ) = _ordinary_prefix_models()
        self._table_cm = _tables(
            self.Principal,
            self.Profile,
            self.PersonalOrganization,
            self.Repository,
            self.ProfileGrant,
        )
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.user = self.Principal.objects.create(username='ord-user')
        self.other = self.Principal.objects.create(username='ord-other')
        self.outsider = self.Principal.objects.create(username='ord-outsider')
        self.read = _permission(self.Repository, 'read_repository')
        self.code = '%s.%s' % (
            self.read.content_type.app_label, self.read.codename,
        )
        self.profile = self.Profile.objects.create(holder=self.user)
        organization = self.PersonalOrganization.objects.create(
            profile=self.profile,
        )
        self.own = self.Repository.objects.create(
            organization=organization, title='ord-own',
        )
        self.sibling = self.Repository.objects.create(
            organization=organization, title='ord-sibling',
        )
        other_profile = self.Profile.objects.create(holder=self.other)
        other_org = self.PersonalOrganization.objects.create(
            profile=other_profile,
        )
        self.foreign = self.Repository.objects.create(
            organization=other_org, title='ord-foreign',
        )
        self.ProfileGrant.objects.create(
            user=self.user, profile=self.profile, permission=self.read,
        )
        self.handle = _handle('tests.core.issue266.ordinary-prefix')
        self.record = self.handle.register(
            trust=self.ProfileGrant,
            user='user',
            permission='permission',
            content=_ORDINARY_PREFIX,
        )

    def tearDown(self):
        ContentType.objects.clear_cache()
        super().tearDown()

    def test_prefix_registers_and_covers_that_organization_only(self):
        self.assertEqual(
            self.record.content_path,
            ('profile', 'personal_organization_ord', 'repositories'),
        )
        self.assertIs(self.record.content_model, self.Repository)
        self.assertEqual(self.handle.registry.delegations, ())
        with _listed(self.handle):
            self.assertTrue(self.user.has_perm(self.code, self.own))
            self.assertEqual(
                set(self.Repository.objects.permitted(self.read, self.user)),
                {self.own, self.sibling},
            )
            self.assertIn(
                self.code, self.user.get_all_permissions(self.own),
            )
            self.assertIn(
                self.user, set(self.own.get_permitted_users(self.read)),
            )
            self.assertNotIn(
                self.outsider, set(self.own.get_permitted_users(self.read)),
            )
            self.assertFalse(self.user.has_perm(self.code, self.foreign))

    def test_missing_organization_fails_closed(self):
        bare = self.Principal.objects.create(username='ord-bare')
        bare_profile = self.Profile.objects.create(holder=bare)
        self.ProfileGrant.objects.create(
            user=bare, profile=bare_profile, permission=self.read,
        )
        with _listed(self.handle):
            self.assertFalse(bare.has_perm(self.code, self.foreign))
            self.assertEqual(
                list(self.Repository.objects.permitted(self.read, bare)),
                [],
            )

    def test_policy_lock_uses_the_prefix_and_has_no_delegation(self):
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[self.handle]),
        )
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        self.assertEqual(trust['root'], self.ProfileGrant._meta.label)
        self.assertEqual(trust['content']['path'], _ORDINARY_PREFIX)
        self.assertNotIn('delegations', content)
        for operation in (
            'permitted', 'has_perm', 'get_all_permissions',
            'get_permitted_users',
        ):
            sql = content[operation]['sql']
            self.assertEqual(sql.count('"issue266_ord_profile_grant"'), 1)
            self.assertIn('issue266_ord_organization', sql)
            self.assertIn('issue266_ord_repository', sql)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ReverseOneToOneGrammarTest(TestCase):
    """A reverse one-to-one is a prefix, not a terminal or a gateway."""

    def _models(self):
        class Principal(models.Model):
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'

        class PersonalProfile(models.Model):
            user = models.OneToOneField(
                Principal, related_name='personal_profile_grammar',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class PersonalOrganization(models.Model):
            profile = models.OneToOneField(
                PersonalProfile, related_name='personal_organization_grammar',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Repository(models.Model):
            organization = models.ForeignKey(
                PersonalOrganization, related_name='repositories',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class PersonalDelegation(models.Model):
            delegate = models.ForeignKey(
                Principal, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                Principal, related_name='+', on_delete=models.CASCADE,
            )
            allowed_permissions = models.ManyToManyField(Permission)

            class Meta:
                app_label = 'trusts_tests'

        class ProfileGrant(models.Model):
            user = models.ForeignKey(
                Principal, on_delete=models.CASCADE,
            )
            profile = models.ForeignKey(
                PersonalProfile, on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        return (
            Principal, PersonalProfile, PersonalOrganization, Repository,
            PersonalDelegation, ProfileGrant,
        )

    def test_terminal_and_gateway_are_rejected(self):
        (
            _principal, _profile, _organization, _repository,
            delegation, grant,
        ) = self._models()
        rejected = (
            (
                delegation,
                {
                    'delegate': 'delegate',
                    'sponsor': 'sponsor',
                    'condition': lambda relationship, permission: (
                        relationship.allowed_permissions.contains(permission)
                    ),
                },
                'sponsor__personal_profile_grammar',
            ),
            (
                delegation,
                {
                    'delegate': 'delegate',
                    'sponsor': 'sponsor',
                    'condition': lambda relationship, permission: (
                        relationship.allowed_permissions.contains(permission)
                    ),
                },
                (
                    'sponsor__personal_profile_grammar'
                    '__personal_organization_grammar'
                ),
            ),
            (
                grant,
                {'user': 'user', 'permission': 'permission'},
                'profile__personal_organization_grammar',
            ),
        )
        for trust, extra, content in rejected:
            with self.subTest(content=content):
                handle = _handle()
                with self.assertNumQueries(0):
                    with self.assertRaisesRegex(
                        TrustsConfigurationError,
                        'not a valid content terminal or gateway',
                    ):
                        handle.register(trust=trust, content=content, **extra)
                self.assertEqual(handle.registry.records, ())
                self.assertEqual(handle.registry.delegations, ())

    def test_two_prefix_chain_registers(self):
        (
            _principal, _profile, _organization, repository,
            delegation, _grant,
        ) = self._models()
        handle = _handle()
        with self.assertNumQueries(0):
            record = handle.register(
                trust=delegation,
                delegate='delegate',
                sponsor='sponsor',
                content=(
                    'sponsor__personal_profile_grammar'
                    '__personal_organization_grammar__repositories'
                ),
                condition=lambda relationship, permission: (
                    relationship.allowed_permissions.contains(permission)
                ),
            )
        self.assertEqual(
            record.content_path,
            (
                'sponsor', 'personal_profile_grammar',
                'personal_organization_grammar', 'repositories',
            ),
        )
        self.assertIs(record.content_model, repository)


class DelegationRootGuardTest(TestCase):
    """Same-root duplicate and conflict stay rejected."""

    def _register(self, handle, **extra):
        payload = {
            'trust': DocumentDelegation,
            'delegate': 'delegate',
            'sponsor': 'sponsor',
            'content': 'document',
            'condition': lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        }
        payload.update(extra)
        return handle.register(**payload)

    def test_missing_root_lookup_fails_closed(self):
        handle = _handle()
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'No delegated registration',
            ):
                handle.registry.delegations_for_root(DocumentDelegation)
        self.assertEqual(handle.registry.delegations, ())

    def test_frozen_registry_rejects_delegation(self):
        handle = _handle()
        handle.registry.freeze()
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'frozen TrustsRegistry',
            ):
                self._register(handle)
            delegation = Ref(DocumentDelegation)
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'frozen TrustsRegistry',
            ):
                handle.registry.register_delegation(
                    content=delegation.document,
                    delegate=delegation.delegate,
                    sponsor=delegation.sponsor,
                )
        self.assertEqual(handle.registry.delegations, ())

    def test_delegate_and_sponsor_must_share_a_principal_model(self):
        handle = _handle()
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'same principal model',
            ):
                self._register(handle, sponsor='document')
        self.assertEqual(handle.registry.delegations, ())

    def test_refs_from_two_roots_are_rejected(self):
        registry = TrustsRegistry()
        delegation = Ref(DocumentDelegation)
        grant = Ref(DocumentGrant)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'same root model',
            ):
                registry.register_delegation(
                    content=delegation.document,
                    delegate=delegation.delegate,
                    sponsor=grant.user,
                )
        self.assertEqual(registry.delegations, ())

    def test_exact_duplicate_on_one_root_is_rejected(self):
        handle = _handle()
        self._register(handle)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'Duplicate delegated registration',
            ):
                self._register(handle)
        self.assertEqual(len(handle.registry.delegations), 1)

    def test_same_root_same_content_terminal_remains_a_conflict(self):
        handle = _handle()
        self._register(handle)
        with self.assertNumQueries(0):
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'Conflicting delegated registration',
            ):
                self._register(
                    handle,
                    condition=lambda relationship: (
                        relationship.delegate == relationship.sponsor
                    ),
                )
        self.assertEqual(len(handle.registry.delegations), 1)

    def test_same_root_different_content_terminal_is_stored(self):
        handle = _handle()
        self._register(handle)
        second = self._register(handle, content='delegate')
        rows = handle.registry.delegations_for_root(DocumentDelegation)
        self.assertEqual(rows, handle.registry.delegations)
        self.assertEqual(len(rows), 2)
        self.assertIs(second.content_model, get_user_model())
        self.assertEqual(second.content_path, ('delegate',))


class DelegatedAuthorityLiveTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._created_myapp_tables = False
        if 'myapp_document' not in connection.introspection.table_names():
            with connection.schema_editor() as editor:
                editor.create_model(Document)
                editor.create_model(DocumentGrant)
                editor.create_model(DocumentDelegation)
            cls._created_myapp_tables = True
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        if cls._created_myapp_tables:
            with connection.schema_editor() as editor:
                editor.delete_model(DocumentDelegation)
                editor.delete_model(DocumentGrant)
                editor.delete_model(Document)

    def setUp(self):
        ContentType.objects.clear_cache()
        if not kernel_host_listed():
            handle = _document_host_handle()
            _PairDocumentBackend.handle = handle
            self.addCleanup(
                lambda: setattr(_PairDocumentBackend, 'handle', None),
            )
            settings_override = override_settings(AUTHENTICATION_BACKENDS=(
                'tests.core.test_issue266._PairDocumentBackend',
            ))
            settings_override.enable()
            self.addCleanup(settings_override.disable)
            relationship_handles = patch(
                'trusts.apps._relationship_implementation_handles',
                return_value=(handle,),
            )
            relationship_handles.start()
            self.addCleanup(relationship_handles.stop)
        User = get_user_model()
        self.sponsor = User.objects.create_user('sponsor-266', password='x')
        self.delegate = User.objects.create_user('delegate-266', password='x')
        self.second_delegate = User.objects.create_user(
            'second-delegate-266', password='x',
        )
        self.outsider = User.objects.create_user('outsider-266', password='x')
        self.change = _permission(Document, 'change_document')
        self.delete = _permission(Document, 'delete_document')
        self.document = Document.objects.create(title='delegated-266')
        DocumentGrant.objects.create(
            document=self.document,
            user=self.sponsor,
            permission=self.change,
        )
        relationship = DocumentDelegation.objects.create(
            document=self.document,
            delegate=self.delegate,
            sponsor=self.sponsor,
        )
        relationship.allowed_permissions.add(self.change)

    def tearDown(self):
        ContentType.objects.clear_cache()

    def test_object_queryset_enumeration_and_reverse_agree(self):
        with self.assertNumQueries(1):
            self.assertTrue(self.delegate.has_perm(
                'myapp.change_document', self.document,
            ))
        with self.assertNumQueries(1):
            permitted = list(
                PermittedQuerySet(
                    model=Document, using=Document.objects.db,
                ).permitted(self.change, self.delegate)
            )
        self.assertEqual(permitted, [self.document])
        with self.assertNumQueries(1):
            permissions = self.delegate.get_all_permissions(self.document)
        self.assertIn('myapp.change_document', permissions)
        with self.assertNumQueries(1):
            users = set(self.document.get_permitted_users(self.change))
        self.assertIn(self.delegate, users)
        self.assertIn(self.sponsor, users)
        self.assertNotIn(self.outsider, users)

    def test_permission_scope_and_live_sponsor_ceiling_both_restrict(self):
        self.assertFalse(self.delegate.has_perm(
            'myapp.delete_document', self.document,
        ))
        relationship = DocumentDelegation.objects.get(delegate=self.delegate)
        relationship.allowed_permissions.add(self.delete)
        self.assertFalse(self.delegate.has_perm(
            'myapp.delete_document', self.document,
        ))
        DocumentGrant.objects.filter(user=self.sponsor).delete()
        self.assertFalse(self.delegate.has_perm(
            'myapp.change_document', self.document,
        ))

    def test_inactive_delegate_or_sponsor_fails_closed(self):
        self.delegate.is_active = False
        self.delegate.save(update_fields=['is_active'])
        self.assertFalse(self.delegate.has_perm(
            'myapp.change_document', self.document,
        ))
        self.delegate.is_active = True
        self.delegate.save(update_fields=['is_active'])
        self.sponsor.is_active = False
        self.sponsor.save(update_fields=['is_active'])
        self.assertFalse(self.delegate.has_perm(
            'myapp.change_document', self.document,
        ))
        self.assertNotIn(
            self.delegate,
            set(self.document.get_permitted_users(self.change)),
        )

    def test_delegated_authority_cannot_sponsor_another_delegation(self):
        relationship = DocumentDelegation.objects.create(
            document=self.document,
            delegate=self.second_delegate,
            sponsor=self.delegate,
        )
        relationship.allowed_permissions.add(self.change)
        self.assertFalse(self.second_delegate.has_perm(
            'myapp.change_document', self.document,
        ))

    def test_sponsor_grant_may_come_from_another_relationship_handle(self):
        grant_handle = _handle('tests.core.issue266.grants')
        grant_handle.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        delegation_handle = _handle('tests.core.issue266.delegations')
        delegation_handle.register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )
        handles = (grant_handle, delegation_handle)

        granted = _compile_granted(
            (delegation_handle,), Document.objects.all(), self.delegate,
            self.change, sponsor_handles=handles,
        )
        self.assertIsNotNone(granted)
        self.assertTrue(Document.objects.filter(granted).exists())

        permitted = permitted_queryset(
            Document.objects.all(), self.change, self.delegate,
            handles=handles,
        )
        self.assertEqual(list(permitted), [self.document])

        permissions = _compile_common_permissions(
            (delegation_handle,), self.document, self.delegate,
            sponsor_handles=handles,
        )
        self.assertEqual(list(permissions), [self.change])

        users = lock_permitted_users_queryset(
            delegation_handle, self.document, self.change, handles=handles,
        )
        self.assertEqual(list(users), [self.delegate])

    def test_policy_lock_exports_delegation_and_correlated_sql(self):
        handle = _handle('tests.core.issue266.policy')
        handle.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        handle.register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )

        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        content = document['backends'][0]['contents'][0]
        delegation = content['delegations'][0]
        self.assertEqual(delegation['delegate']['path'], 'delegate')
        self.assertEqual(delegation['sponsor']['path'], 'sponsor')
        self.assertEqual(delegation['content']['path'], 'document')
        for operation in (
            'permitted', 'has_perm', 'get_all_permissions',
            'get_permitted_users',
        ):
            sql = content[operation]['sql']
            self.assertIn('myapp_documentdelegation', sql)
            self.assertIn('myapp_documentgrant', sql)

    def test_policy_lock_uses_a_sponsor_grant_from_another_handle(self):
        grant_handle = _handle('tests.core.issue266.split-grants')
        grant_handle.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
        )
        delegation_handle = _handle('tests.core.issue266.split-delegations')
        delegation_handle.register(
            trust=DocumentDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='document',
            condition=lambda relationship, permission: (
                relationship.allowed_permissions.contains(permission)
            ),
        )
        _PairDocumentBackend.handle = delegation_handle
        self.addCleanup(lambda: setattr(_PairDocumentBackend, 'handle', None))
        with override_settings(AUTHENTICATION_BACKENDS=(
            'tests.core.test_issue266._PairDocumentBackend',
        )), patch(
            'trusts.apps._relationship_implementation_handles',
            return_value=(grant_handle, delegation_handle),
        ):
            self.assertTrue(self.delegate.has_perm(
                'myapp.change_document', self.document,
            ))
            self.assertFalse(self.second_delegate.has_perm(
                'myapp.change_document', self.document,
            ))
        document = _load_policy_sql_document(
            render_policy_sql_bytes(
                handles=[grant_handle, delegation_handle],
            ),
        )
        by_path = {row['path']: row for row in document['backends']}
        content = by_path[
            'tests.core.issue266.split-delegations'
        ]['contents'][0]
        self.assertNotIn('trusts', content)
        self.assertEqual(
            content['delegations'][0]['sponsor']['path'], 'sponsor',
        )
        for operation in (
            'permitted', 'has_perm', 'get_all_permissions',
            'get_permitted_users',
        ):
            sql = content[operation]['sql']
            self.assertIn('myapp_documentdelegation', sql)
            self.assertIn('myapp_documentgrant', sql)

