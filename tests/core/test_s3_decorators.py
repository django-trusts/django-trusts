"""Isolated kernel tests for #47 S3 (native decorators / request binders).

``require_authorized`` routes through S1 ``filter_authorized``. Resource
identity is URL kwargs / ``K`` / ``G`` / ``O`` only. Isolated registries.
Does not close #47. Does not implement S4–S5.
"""

import inspect
import re
from pathlib import Path
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from trusts.context import ContextRegistry
from trusts.decorators import G, K, O, P, require_authorized, request_passes_test
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


def _ok_view(request, **kwargs):
    """S3 decorated view."""
    return HttpResponse('ok')


class S3DecoratorContractTest(TestCase):
    def test_decorators_module_has_no_product_nouns_or_perm_parser(self):
        from trusts import decorators
        source = Path(inspect.getfile(decorators)).read_text()
        for noun in ('Trust', 'Content', 'Junction', 'GitHub'):
            self.assertIsNone(
                re.search(r'\b%s\b' % noun, source),
                '%r appears as a product noun in trusts.decorators' % (noun,),
            )
        self.assertNotIn('parse_perm_code', source)
        self.assertNotIn('ContentType', source)
        self.assertNotIn('has_perm', source)
        self.assertNotIn('app.action_model', source)
        self.assertNotIn('permission_required', source)

    def test_wrapped_view_metadata_is_preserved(self):
        context, trustee = _s1_maps()
        wrapped = require_authorized(
            'read', resource_model=S1Repository, resource_kwarg='pk',
            context=context, trustee=trustee,
        )(_ok_view)
        self.assertEqual(wrapped.__name__, '_ok_view')
        self.assertEqual(wrapped.__doc__, 'S3 decorated view.')

    def test_callable_selector_is_rejected_as_config(self):
        with self.assertRaises(AuthorizationConfigError):
            require_authorized(
                'read', resource_model=S1Repository, pk=lambda request: 1,
            )
        with self.assertRaises(AuthorizationConfigError):
            P('read', resource_model=S1Repository, pk=S1Repository.objects.get)

    def test_p_rejects_non_p_boolean_operands(self):
        with self.assertRaises(TypeError):
            P('read') & 'write'
        with self.assertRaises(TypeError):
            P('read') | 1


class S3DecoratorFixtureMixin(object):
    def setUp(self):
        super(S3DecoratorFixtureMixin, self).setUp()
        self.factory = RequestFactory()
        self.org = S1Organization.objects.create(name='acme')
        self.team = S1Team.objects.create(organization=self.org, name='writers')
        self.member = S1Account.objects.create(name='member')
        self.stranger = S1Account.objects.create(name='stranger')
        self.team.members.add(self.member)
        self.read = S1Operation.objects.create(code='read')
        self.write = S1Operation.objects.create(code='write')
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
        self.runtime = dict(context=self.context, trustee=self.trustee)
        self.decorate = dict(
            resource_model=S1Repository,
            context=self.context,
            trustee=self.trustee,
        )

    def _wrap(self, operation='read', **kwargs):
        options = dict(self.decorate)
        options.update(kwargs)
        return require_authorized(operation, **options)(_ok_view)

    def _get(self, user, path='/', data=None, **kwargs):
        request = self.factory.get(path, data=data or {})
        request.user = user
        return request


class S3BindingAndDecisionTest(S3DecoratorFixtureMixin, TestCase):
    def test_url_kwarg_granted_is_one_combined_query(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(1):
            response = view(request, pk=self.repo_a.pk)
        self.assertEqual(response.content, b'ok')
        self.assertTrue(
            is_authorized(self.member, 'read', self.repo_a, **self.runtime)
        )

    def test_url_kwarg_denied_uses_existence_query(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_b.pk)
        request = self._get(self.stranger)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)

    def test_missing_kwarg_is_404_without_sql(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request, pk='')

    def test_unknown_pk_is_404(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(self.member)
        missing_pk = self.repo_a.pk + self.repo_b.pk + 1000
        with self.assertNumQueries(2):
            with self.assertRaises(Http404):
                view(request, pk=missing_pk)

    def test_k_selector_matches_resource_kwarg(self):
        view = self._wrap(pk=K('repo_id'))
        request = self._get(self.member)
        with self.assertNumQueries(1):
            response = view(request, repo_id=self.repo_a.pk)
        self.assertEqual(response.content, b'ok')
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, repo_id=self.repo_b.pk)

    def test_g_selector_reads_get(self):
        view = self._wrap(pk=G('id'))
        request = self._get(self.member, data={'id': str(self.repo_a.pk)})
        with self.assertNumQueries(1):
            response = view(request)
        self.assertEqual(response.content, b'ok')
        missing = self._get(self.member)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(missing)

    def test_o_selector_reads_post(self):
        view = self._wrap(pk=O('id'))
        request = self.factory.post('/', data={'id': str(self.repo_a.pk)})
        request.user = self.member
        with self.assertNumQueries(1):
            response = view(request)
        self.assertEqual(response.content, b'ok')
        denied = self.factory.post('/', data={'id': str(self.repo_b.pk)})
        denied.user = self.member
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(denied)
        missing = self.factory.post('/')
        missing.user = self.member
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(missing)

    def test_operation_instance_is_accepted(self):
        view = self._wrap(self.read, resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(1):
            self.assertEqual(view(request, pk=self.repo_a.pk).content, b'ok')


class S3UnusablePrincipalTest(S3DecoratorFixtureMixin, TestCase):
    def test_anonymous_existing_resource_is_403_one_existence_query(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(AnonymousUser())
        with self.assertNumQueries(1):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)

    def test_anonymous_missing_key_is_404_without_sql(self):
        view = self._wrap(resource_kwarg='pk')
        request = self._get(AnonymousUser())
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request)

    def test_inactive_and_unauthenticated_are_403(self):
        view = self._wrap(resource_kwarg='pk')
        self.member.is_active = False
        request = self._get(self.member)
        with self.assertNumQueries(1):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)
        del self.member.is_active
        self.member.is_authenticated = False
        with self.assertNumQueries(1):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)


class S3UnknownOperationTest(S3DecoratorFixtureMixin, TestCase):
    def test_unknown_operation_data_is_403_when_resource_exists(self):
        view = self._wrap('missing', resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)


class S3ConfigErrorTest(S3DecoratorFixtureMixin, TestCase):
    def test_unregistered_resource_is_403(self):
        note = S1UnregisteredNote.objects.create(
            repository=self.repo_a, text='nope',
        )
        view = require_authorized(
            'read', resource_model=S1UnregisteredNote, resource_kwarg='pk',
            context=self.context, trustee=self.trustee,
        )(_ok_view)
        request = self._get(self.member)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.member, 'read', note,
                context=self.context, trustee=self.trustee,
            )
        with self.assertRaises(PermissionDenied):
            view(request, pk=note.pk)

    def test_empty_adapters_is_403(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
            operation_lookup='code',
        )
        view = require_authorized(
            'read', resource_model=S1Repository, resource_kwarg='pk',
            context=context, trustee=trustee,
        )(_ok_view)
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)

    def test_string_without_lookup_is_403(self):
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
        view = require_authorized(
            'read', resource_model=S1Repository, resource_kwarg='pk',
            context=context, trustee=trustee,
        )(_ok_view)
        request = self._get(self.member)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.member, 'read', self.repo_a,
                context=context, trustee=trustee,
            )
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)

    def test_missing_resource_model_is_403(self):
        view = require_authorized(
            'read', resource_kwarg='pk',
            context=self.context, trustee=self.trustee,
        )(_ok_view)
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)

    def test_missing_identity_selector_is_403(self):
        view = self._wrap()
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)


class S3SuperuserContractTest(S3DecoratorFixtureMixin, TestCase):
    def test_is_superuser_does_not_bypass_object_policy(self):
        self.member.is_superuser = True
        view = self._wrap(resource_kwarg='pk')
        request = self._get(self.member)
        with self.assertNumQueries(1):
            self.assertEqual(view(request, pk=self.repo_a.pk).content, b'ok')
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_b.pk)

    def test_django_superuser_does_not_bypass_decorator(self):
        superuser = User.objects.create_superuser(
            'root', 'root@example.com', 'secret',
        )
        self.assertTrue(superuser.is_active)
        self.assertTrue(superuser.is_superuser)
        view = self._wrap(resource_kwarg='pk')
        request = self._get(superuser)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)


class S3BooleanPTest(S3DecoratorFixtureMixin, TestCase):
    def test_or_grants_when_one_leaf_matches(self):
        view = self._wrap(
            P('read', resource_kwarg='pk') | P('write', resource_kwarg='pk'),
        )
        request = self._get(self.member)
        with self.assertNumQueries(1):
            self.assertEqual(view(request, pk=self.repo_a.pk).content, b'ok')

    def test_and_requires_both_operations(self):
        view = self._wrap(
            P('read', resource_kwarg='pk') & P('write', resource_kwarg='pk'),
        )
        request = self._get(self.member)
        # read leaf grants in one combined query; write leaf then misses
        # (combined) and confirms existence — 3 SQL, not one.
        with self.assertNumQueries(3):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.write,
        )
        self.team.bundles.get().operations.add(self.write)
        with self.assertNumQueries(2):
            self.assertEqual(view(request, pk=self.repo_a.pk).content, b'ok')

    def test_p_inherits_decorator_resource_model(self):
        view = require_authorized(
            P('read', pk=K('pk')),
            resource_model=S1Repository,
            context=self.context,
            trustee=self.trustee,
        )(_ok_view)
        request = self._get(self.member)
        with self.assertNumQueries(1):
            self.assertEqual(view(request, pk=self.repo_a.pk).content, b'ok')


class S3LoginRedirectTest(S3DecoratorFixtureMixin, TestCase):
    @override_settings(LOGIN_URL='/accounts/login/')
    def test_unauthorized_redirects_when_raise_exception_is_false(self):
        view = self._wrap(resource_kwarg='pk', raise_exception=False)
        request = self._get(self.stranger, path='/repos/%s/' % self.repo_a.pk)
        response = view(request, pk=self.repo_a.pk)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response['Location'])
        self.assertIn('next=', response['Location'])

    @override_settings(LOGIN_URL='/accounts/login/')
    def test_missing_resource_is_still_404_when_login_redirect_configured(self):
        view = self._wrap(resource_kwarg='pk', raise_exception=False)
        request = self._get(self.member)
        with self.assertRaises(Http404):
            view(request)

    @override_settings(LOGIN_URL='/accounts/login/')
    def test_config_error_stays_403_when_login_redirect_configured(self):
        view = require_authorized(
            'read', resource_model=S1UnregisteredNote, resource_kwarg='pk',
            raise_exception=False,
            context=self.context, trustee=self.trustee,
        )(_ok_view)
        note = S1UnregisteredNote.objects.create(
            repository=self.repo_a, text='nope',
        )
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=note.pk)


class S3RequestPassesTestHelper(TestCase):
    def test_true_calls_view_false_redirects(self):
        factory = RequestFactory()

        @request_passes_test(lambda request, **kwargs: request.GET.get('ok') == '1')
        def view(request, **kwargs):
            return HttpResponse('ok')

        allowed = factory.get('/', data={'ok': '1'})
        self.assertEqual(view(allowed).content, b'ok')
        denied = factory.get('/secret/')
        response = view(denied)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response['Location'])

    def test_helper_preserves_wraps(self):
        def probe(request, **kwargs):
            return True

        @request_passes_test(probe)
        def named_view(request, **kwargs):
            """helper doc"""
            return HttpResponse('ok')

        self.assertEqual(named_view.__name__, 'named_view')
        self.assertEqual(named_view.__doc__, 'helper doc')
