"""Isolated kernel tests for #47 S2 (object-only authorization backend).

``ObjectAuthorizationBackend`` is a ``BaseBackend``. Object checks route
through S1 ``is_authorized``. ``AuthorizationConfigError`` becomes
denial. Isolated registries only. Does not close #47. Does not
implement S3–S4.
"""

import inspect
import re
from pathlib import Path

from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth.models import AnonymousUser, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from trusts.backends import (
    ObjectAuthorizationBackend,
    ObjectAuthorizationModelBackend,
)
from trusts.context import ContextRegistry
from trusts.runtime import AuthorizationConfigError, is_authorized
from trusts.trustee import TrusteeRegistry
from tests.core.test_s1_kernel import S1_DIRECT, _s1_maps
from tests.models import (
    S1Account,
    S1Bundle,
    S1DirectGrant,
    S1Operation,
    S1Organization,
    S1Repository,
    S1Team,
    S1TeamGrant,
    S1UnregisteredNote,
)


class S2BackendContractTest(TestCase):
    def test_generic_backend_is_object_only_basebackend(self):
        self.assertTrue(issubclass(ObjectAuthorizationBackend, BaseBackend))
        self.assertFalse(issubclass(ObjectAuthorizationBackend, ModelBackend))
        self.assertTrue(
            issubclass(ObjectAuthorizationModelBackend, ObjectAuthorizationBackend)
        )
        self.assertTrue(issubclass(ObjectAuthorizationModelBackend, ModelBackend))

    def test_backends_module_has_no_product_nouns_or_perm_parser(self):
        from trusts import backends
        source = Path(inspect.getfile(backends)).read_text()
        for noun in ('Trust', 'Content', 'Junction', 'GitHub'):
            self.assertIsNone(
                re.search(r'\b%s\b' % noun, source),
                '%r appears as a product noun in trusts.backends' % (noun,),
            )
        self.assertNotIn('parse_perm_code', source)
        self.assertNotIn('is_content', source)
        self.assertNotIn('is_superuser', source)
        self.assertNotIn('app.action_model', source)

    def test_authenticate_abstains(self):
        backend = ObjectAuthorizationBackend()
        self.assertIsNone(backend.authenticate(None))
        self.assertIsNone(
            backend.authenticate(None, username='pat', password='secret'),
        )


class S2ObjectHasPermTest(TestCase):
    def setUp(self):
        super(S2ObjectHasPermTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.team = S1Team.objects.create(organization=self.org, name='writers')
        self.member = S1Account.objects.create(name='member')
        self.stranger = S1Account.objects.create(name='stranger')
        self.team.members.add(self.member)
        self.read = S1Operation.objects.create(code='read')
        self.repo_a = S1Repository.objects.create(
            organization=self.org, title='repo-a',
        )
        self.repo_b = S1Repository.objects.create(
            organization=self.org, title='repo-b',
        )
        bundle = S1Bundle.objects.create(team=self.team, name='reader')
        bundle.operations.add(self.read)
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.read,
        )
        self.context, self.trustee = _s1_maps()
        self.backend = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )
        self.runtime = dict(context=self.context, trustee=self.trustee)

    def test_object_success_and_denial_via_has_perm(self):
        with self.assertNumQueries(1):
            self.assertTrue(
                self.backend.has_perm(self.member, 'read', self.repo_a)
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.backend.has_perm(self.member, 'read', self.repo_b)
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.backend.has_perm(self.stranger, 'read', self.repo_a)
            )
        with self.assertNumQueries(1):
            self.assertTrue(
                self.backend.has_perm(self.member, self.read, self.repo_a)
            )
        self.assertEqual(
            self.backend.has_perm(self.member, 'read', self.repo_a),
            is_authorized(self.member, 'read', self.repo_a, **self.runtime),
        )

    def test_django_perm_string_is_not_parsed(self):
        django_shaped = 'trusts_tests.read_s1repository'
        with self.assertNumQueries(1):
            self.assertFalse(
                self.backend.has_perm(self.member, django_shaped, self.repo_a)
            )

    def test_obj_none_is_false_without_sql(self):
        with self.assertNumQueries(0):
            self.assertFalse(self.backend.has_perm(self.member, 'read'))
            self.assertFalse(
                self.backend.has_perm(self.member, 'read', obj=None)
            )
            self.assertFalse(
                self.backend.has_perm(self.member, 'trusts_tests.read_s1repository')
            )


class S2OrdinaryDenialTest(TestCase):
    def setUp(self):
        super(S2OrdinaryDenialTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')
        self.context, self.trustee = _s1_maps()
        self.backend = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )

    def test_anonymous_user_ordinary_denial(self):
        with self.assertNumQueries(0):
            self.assertFalse(
                self.backend.has_perm(AnonymousUser(), 'read', self.repo)
            )

    def test_inactive_and_unauthenticated_ordinary_denial(self):
        self.account.is_active = False
        with self.assertNumQueries(0):
            self.assertFalse(
                self.backend.has_perm(self.account, 'read', self.repo)
            )
        del self.account.is_active
        self.account.is_authenticated = False
        with self.assertNumQueries(0):
            self.assertFalse(
                self.backend.has_perm(self.account, 'read', self.repo)
            )

    def test_unknown_operation_data_ordinary_denial(self):
        with self.assertNumQueries(1):
            self.assertFalse(
                self.backend.has_perm(self.account, 'missing', self.repo)
            )


class S2ConfigErrorDenialTest(TestCase):
    def setUp(self):
        super(S2ConfigErrorDenialTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')
        self.context, self.trustee = _s1_maps()
        self.backend = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )

    def test_unregistered_resource_denies_without_raising(self):
        note = S1UnregisteredNote.objects.create(
            repository=self.repo, text='nope',
        )
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.account, 'read', note,
                context=self.context, trustee=self.trustee,
            )
        self.assertFalse(self.backend.has_perm(self.account, 'read', note))

    def test_wrong_model_and_raw_pk_deny_without_raising(self):
        self.assertFalse(self.backend.has_perm(self.repo, 'read', self.repo))
        self.assertFalse(
            self.backend.has_perm(self.account.pk, 'read', self.repo)
        )
        self.assertFalse(
            self.backend.has_perm(self.account, self.read.pk, self.repo)
        )

    def test_string_without_lookup_denies_without_raising(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        )
        trustee.register(
            name=S1_DIRECT,
            trustee_model=S1Account,
            grant_model=S1DirectGrant,
            trustee_path='account',
            scope_path='repository',
            operation_path='operation',
        )
        backend = ObjectAuthorizationBackend(context=context, trustee=trustee)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.account, 'read', self.repo,
                context=context, trustee=trustee,
            )
        self.assertFalse(backend.has_perm(self.account, 'read', self.repo))

    def test_empty_adapters_deny_without_raising(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
            operation_lookup='code',
        )
        backend = ObjectAuthorizationBackend(context=context, trustee=trustee)
        self.assertFalse(backend.has_perm(self.account, 'read', self.repo))


class S2SuperuserContractTest(TestCase):
    def setUp(self):
        super(S2SuperuserContractTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')
        S1DirectGrant.objects.create(
            account=self.account, repository=self.repo, operation=self.read,
        )
        self.other = S1Repository.objects.create(
            organization=self.org, title='other',
        )
        self.context, self.trustee = _s1_maps()
        self.backend = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )

    def test_is_superuser_does_not_grant_object_access(self):
        self.account.is_superuser = True
        self.assertTrue(self.backend.has_perm(self.account, 'read', self.repo))
        self.assertFalse(
            self.backend.has_perm(self.account, 'read', self.other)
        )

    def test_django_superuser_does_not_bypass_generic_backend(self):
        superuser = User.objects.create_superuser(
            'root', 'root@example.com', 'secret',
        )
        self.assertTrue(superuser.is_active)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.has_perm('anything.goes', self.repo))
        self.assertFalse(self.backend.has_perm(superuser, 'read', self.repo))
        self.assertFalse(self.backend.has_perm(superuser, 'read'))


class S2CoexistenceTest(TestCase):
    def setUp(self):
        super(S2CoexistenceTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')
        S1DirectGrant.objects.create(
            account=self.account, repository=self.repo, operation=self.read,
        )
        self.context, self.trustee = _s1_maps()
        self.user = User.objects.create_user('pat', password='secret')
        content_type = ContentType.objects.get_for_model(S1Repository)
        self.model_perm = Permission.objects.get(
            content_type=content_type, codename='add_s1repository',
        )
        self.perm_code = '%s.add_s1repository' % content_type.app_label
        self.user.user_permissions.add(self.model_perm)
        self.user = User._default_manager.get(pk=self.user.pk)

    def test_generic_backend_does_not_grant_model_perms(self):
        backend = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )
        self.assertFalse(backend.has_perm(self.user, self.perm_code))
        self.assertFalse(backend.has_perm(self.user, self.perm_code, self.repo))
        self.assertTrue(backend.has_perm(self.account, 'read', self.repo))

    @override_settings(AUTHENTICATION_BACKENDS=(
        'django.contrib.auth.backends.ModelBackend',
        'trusts.backends.ObjectAuthorizationBackend',
    ))
    def test_modelbackend_coexistence_does_not_widen_object_access(self):
        self.assertTrue(self.user.has_perm(self.perm_code))
        self.assertFalse(self.user.has_perm(self.perm_code, self.repo))
        model = ModelBackend()
        generic = ObjectAuthorizationBackend(
            context=self.context, trustee=self.trustee,
        )
        self.assertTrue(model.has_perm(self.user, self.perm_code))
        self.assertFalse(model.has_perm(self.user, self.perm_code, self.repo))
        self.assertFalse(generic.has_perm(self.user, self.perm_code))
        self.assertFalse(generic.has_perm(self.user, self.perm_code, self.repo))
        self.assertTrue(generic.has_perm(self.account, 'read', self.repo))

    def test_optional_modelbackend_convenience_dispatch_boundary(self):
        backend = ObjectAuthorizationModelBackend(
            context=self.context, trustee=self.trustee,
        )
        self.assertTrue(backend.has_perm(self.user, self.perm_code))
        self.assertFalse(backend.has_perm(self.user, self.perm_code, self.repo))
        self.assertTrue(backend.has_perm(self.account, 'read', self.repo))

        superuser = User.objects.create_superuser(
            'root', 'root@example.com', 'secret',
        )
        self.assertTrue(backend.has_perm(superuser, self.perm_code))
        self.assertFalse(backend.has_perm(superuser, 'read', self.repo))
        self.assertFalse(backend.has_perm(superuser, self.perm_code, self.repo))

        found = backend.authenticate(None, username='pat', password='secret')
        self.assertEqual(found.pk, self.user.pk)
        self.assertIsNone(
            ObjectAuthorizationBackend().authenticate(
                None, username='pat', password='secret',
            )
        )
