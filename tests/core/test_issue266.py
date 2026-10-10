"""Delegated authority registration and one-level correlated grants (#266)."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import SimpleTestCase, TestCase

from tests.core import KernelHostRequiredMixin
from tests.myapp.models import Document, DocumentDelegation, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    RegisteredDelegation,
    TrustsConfigurationError,
    TrustsRegistry,
    _compile_common_permissions,
    _compile_granted,
)
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts._permitted import permitted_queryset
from trusts.query import PermittedQuerySet
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


class DelegatedAuthorityLiveTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
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

