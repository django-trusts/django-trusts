"""Isolated kernel tests for #47 S4 (admin, CBV mixins, stub templates).

List querysets use S1 ``filter_authorized`` before pagination. Object
gates agree with that queryset. ``AuthorizationConfigError`` is 403.
Isolated registries only. Does not close #47. Does not implement S5.
"""

import inspect
import re
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.template.loader import get_template
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.views.generic import DetailView, ListView, UpdateView

from trusts.admin import AuthorizedModelAdmin
from trusts.context import ContextRegistry
from trusts.runtime import AuthorizationConfigError, filter_authorized, is_authorized
from trusts.trustee import TrusteeRegistry
from trusts.views import (
    AuthorizedObjectMixin,
    AuthorizedQuerySetMixin,
    resolve_authorized_object,
)
from tests.core.test_s1_kernel import _s1_maps
from tests.models import (
    S1Account,
    S1Bundle,
    S1Operation,
    S1Organization,
    S1Repository,
    S1Team,
    S1TeamGrant,
    S1UnregisteredNote,
)


class S4ContractTest(SimpleTestCase):
    def test_admin_and_views_have_no_product_nouns_or_perm_parser(self):
        from trusts import admin as admin_mod
        from trusts import views as views_mod
        for module in (admin_mod, views_mod):
            source = Path(inspect.getfile(module)).read_text()
            for noun in ('Trust', 'Content', 'Junction', 'GitHub'):
                self.assertIsNone(
                    re.search(r'\b%s\b' % noun, source),
                    '%r appears as a product noun in %s' % (
                        noun, module.__name__,
                    ),
                )
            self.assertNotIn('parse_perm_code', source)
            self.assertNotIn('ContentType', source)
            self.assertNotIn('has_perm(', source)
            self.assertNotIn('app.action_model', source)
            self.assertNotIn('urlpatterns', source)

    def test_stub_templates_are_under_trusts_namespace(self):
        names = (
            'trusts/authorized_list.html',
            'trusts/authorized_detail.html',
            'trusts/authorized_form.html',
            'trusts/authorized_confirm_delete.html',
        )
        for name in names:
            template = get_template(name)
            source = template.template.source
            self.assertIn('Override with template_name', source)
            for noun in ('Trust', 'Content', 'Junction', 'GitHub', 'Team'):
                self.assertIsNone(
                    re.search(r'\b%s\b' % noun, source),
                    '%r appears in %s' % (noun, name),
                )


class S4FixtureMixin(object):
    def setUp(self):
        super(S4FixtureMixin, self).setUp()
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
        self.repo_c = S1Repository.objects.create(
            organization=self.org, title='repo-c',
        )
        bundle = S1Bundle.objects.create(team=self.team, name='reader')
        bundle.operations.add(self.read)
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.read,
        )
        self.context, self.trustee = _s1_maps()
        self.runtime = dict(context=self.context, trustee=self.trustee)


class S4RepositoryAdmin(AuthorizedModelAdmin):
    list_operation = 'read'
    view_operation = 'read'
    change_operation = 'write'
    delete_operation = 'write'
    list_display = ('title',)


class S4AdminListTest(S4FixtureMixin, TestCase):
    def _admin(self, **attrs):
        attrs.setdefault('context', self.context)
        attrs.setdefault('trustee', self.trustee)
        admin_class = type('BoundAdmin', (S4RepositoryAdmin,), attrs)
        return admin_class(S1Repository, AdminSite(name='s4'))

    def _request(self, user, path='/s4/s1repository/'):
        request = self.factory.get(path)
        request.user = user
        return request

    def test_get_queryset_filters_before_pagination_in_one_sql(self):
        model_admin = self._admin()
        request = self._request(self.member)
        with self.assertNumQueries(1):
            pks = list(
                model_admin.get_queryset(request).values_list('pk', flat=True)
            )
        self.assertEqual(pks, [self.repo_a.pk])
        expected = list(
            filter_authorized(
                S1Repository.objects.all(), self.member, 'read', **self.runtime
            ).values_list('pk', flat=True)
        )
        self.assertEqual(pks, expected)

    def test_changelist_paginates_authorized_queryset_not_all_rows(self):
        model_admin = self._admin(list_per_page=1)
        request = self._request(self.member)
        changelist = model_admin.get_changelist_instance(request)
        self.assertEqual(changelist.result_count, 1)
        self.assertEqual([row.pk for row in changelist.result_list], [self.repo_a.pk])
        self.assertEqual(S1Repository.objects.count(), 3)
        self.assertLessEqual(changelist.paginator.count, 1)

    def test_unusable_principal_list_is_empty_without_auth_exists(self):
        model_admin = self._admin()
        request = self._request(AnonymousUser())
        with self.assertNumQueries(0):
            self.assertEqual(list(model_admin.get_queryset(request)), [])
        self.member.is_active = False
        request = self._request(self.member)
        with self.assertNumQueries(0):
            self.assertEqual(list(model_admin.get_queryset(request)), [])

    def test_stranger_list_is_empty_one_sql(self):
        model_admin = self._admin()
        request = self._request(self.stranger)
        with self.assertNumQueries(1):
            self.assertEqual(list(model_admin.get_queryset(request)), [])


class S4AdminObjectGateTest(S4FixtureMixin, TestCase):
    def _admin(self, **attrs):
        attrs.setdefault('context', self.context)
        attrs.setdefault('trustee', self.trustee)
        admin_class = type('BoundAdmin', (S4RepositoryAdmin,), attrs)
        return admin_class(S1Repository, AdminSite(name='s4'))

    def _request(self, user):
        request = self.factory.get('/s4/s1repository/')
        request.user = user
        return request

    def test_object_and_list_gates_agree(self):
        model_admin = self._admin()
        request = self._request(self.member)
        authorized = set(
            model_admin.get_queryset(request).values_list('pk', flat=True)
        )
        for repo in (self.repo_a, self.repo_b, self.repo_c):
            listed = repo.pk in authorized
            viewed = model_admin.has_view_permission(request, repo)
            self.assertEqual(listed, viewed)
            self.assertEqual(
                viewed,
                is_authorized(self.member, 'read', repo, **self.runtime),
            )

    def test_get_object_granted_is_one_combined_query(self):
        model_admin = self._admin()
        request = self._request(self.member)
        with self.assertNumQueries(1):
            obj = model_admin.get_object(request, str(self.repo_a.pk))
        self.assertEqual(obj.pk, self.repo_a.pk)

    def test_get_object_unauthorized_is_403_not_404(self):
        model_admin = self._admin()
        request = self._request(self.member)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                model_admin.get_object(request, str(self.repo_b.pk))
        missing_pk = self.repo_a.pk + self.repo_b.pk + self.repo_c.pk + 1000
        with self.assertNumQueries(2):
            self.assertIsNone(model_admin.get_object(request, str(missing_pk)))

    def test_change_and_delete_require_write(self):
        model_admin = self._admin()
        request = self._request(self.member)
        self.assertTrue(model_admin.has_view_permission(request, self.repo_a))
        self.assertFalse(model_admin.has_change_permission(request, self.repo_a))
        self.assertFalse(model_admin.has_delete_permission(request, self.repo_a))
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.write,
        )
        self.team.bundles.get().operations.add(self.write)
        self.assertTrue(model_admin.has_change_permission(request, self.repo_a))
        self.assertTrue(model_admin.has_delete_permission(request, self.repo_a))
        self.assertFalse(model_admin.has_change_permission(request, self.repo_b))

    def test_add_is_fail_closed(self):
        model_admin = self._admin()
        request = self._request(self.member)
        self.assertFalse(model_admin.has_add_permission(request))
        self.member.is_superuser = True
        self.assertFalse(model_admin.has_add_permission(request))

    def test_module_permission_does_not_use_django_model_perms(self):
        model_admin = self._admin()
        request = self._request(self.member)
        self.assertTrue(model_admin.has_module_permission(request))
        self.assertTrue(model_admin.has_view_permission(request))
        request = self._request(AnonymousUser())
        self.assertFalse(model_admin.has_module_permission(request))
        self.assertFalse(model_admin.has_view_permission(request))


class S4AdminConfigAndSuperuserTest(S4FixtureMixin, TestCase):
    def _request(self, user):
        request = self.factory.get('/s4/s1repository/')
        request.user = user
        return request

    def test_unregistered_resource_is_403(self):
        admin_class = type('NoteAdmin', (AuthorizedModelAdmin,), dict(
            list_operation='read',
            view_operation='read',
            context=self.context,
            trustee=self.trustee,
        ))
        model_admin = admin_class(S1UnregisteredNote, AdminSite(name='s4'))
        note = S1UnregisteredNote.objects.create(
            repository=self.repo_a, text='nope',
        )
        request = self._request(self.member)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.member, 'read', note,
                context=self.context, trustee=self.trustee,
            )
        with self.assertRaises(PermissionDenied):
            list(model_admin.get_queryset(request))
        with self.assertRaises(PermissionDenied):
            model_admin.get_object(request, str(note.pk))
        self.assertFalse(model_admin.has_view_permission(request, note))

    def test_missing_list_operation_is_403(self):
        admin_class = type('BareAdmin', (AuthorizedModelAdmin,), dict(
            context=self.context,
            trustee=self.trustee,
        ))
        model_admin = admin_class(S1Repository, AdminSite(name='s4'))
        request = self._request(self.member)
        with self.assertRaises(PermissionDenied):
            list(model_admin.get_queryset(request))
        self.assertFalse(model_admin.has_view_permission(request, self.repo_a))
        self.assertFalse(model_admin.has_change_permission(request, self.repo_a))

    def test_callable_operation_is_403(self):
        admin_class = type('CallableAdmin', (S4RepositoryAdmin,), dict(
            list_operation=lambda request: 'read',
            context=self.context,
            trustee=self.trustee,
        ))
        model_admin = admin_class(S1Repository, AdminSite(name='s4'))
        request = self._request(self.member)
        with self.assertRaises(PermissionDenied):
            list(model_admin.get_queryset(request))

    def test_empty_adapters_is_403(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
            operation_lookup='code',
        )
        admin_class = type('EmptyAdmin', (S4RepositoryAdmin,), dict(
            context=context, trustee=trustee,
        ))
        model_admin = admin_class(S1Repository, AdminSite(name='s4'))
        request = self._request(self.member)
        with self.assertRaises(PermissionDenied):
            list(model_admin.get_queryset(request))

    def test_is_superuser_does_not_bypass_object_policy(self):
        admin_class = type('BoundAdmin', (S4RepositoryAdmin,), dict(
            context=self.context, trustee=self.trustee,
        ))
        model_admin = admin_class(S1Repository, AdminSite(name='s4'))
        self.member.is_superuser = True
        request = self._request(self.member)
        self.assertEqual(
            model_admin.get_object(request, str(self.repo_a.pk)).pk,
            self.repo_a.pk,
        )
        with self.assertRaises(PermissionDenied):
            model_admin.get_object(request, str(self.repo_b.pk))
        superuser = User.objects.create_superuser(
            'root', 'root@example.com', 'secret',
        )
        request = self._request(superuser)
        with self.assertRaises(PermissionDenied):
            list(model_admin.get_queryset(request))
        self.assertFalse(model_admin.has_view_permission(request, self.repo_a))


class S4CBVListTest(S4FixtureMixin, TestCase):
    def _view(self, **attrs):
        attrs.setdefault('model', S1Repository)
        attrs.setdefault('list_operation', 'read')
        attrs.setdefault('context', self.context)
        attrs.setdefault('trustee', self.trustee)
        attrs.setdefault('paginate_by', 1)
        attrs.setdefault('ordering', ('pk',))
        view_class = type('RepoList', (AuthorizedQuerySetMixin, ListView), attrs)
        return view_class.as_view()

    def _get(self, user, path='/', data=None):
        request = self.factory.get(path, data=data or {})
        request.user = user
        return request

    def test_list_filters_before_pagination(self):
        view = self._view()
        request = self._get(self.member)
        with self.assertNumQueries(2):
            response = view(request)
            objects = list(response.context_data['object_list'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual([obj.pk for obj in objects], [self.repo_a.pk])
        self.assertEqual(response.context_data['paginator'].count, 1)
        self.assertEqual(S1Repository.objects.count(), 3)
        rendered = response.render()
        self.assertContains(rendered, 'repo-a')
        self.assertNotContains(rendered, 'repo-b')
        self.assertNotContains(rendered, 'repo-c')

    def test_list_equivalents_filter_authorized(self):
        view = self._view(paginate_by=None)
        request = self._get(self.member)
        with self.assertNumQueries(1):
            response = view(request)
            pks = [obj.pk for obj in response.context_data['object_list']]
        expected = list(
            filter_authorized(
                S1Repository.objects.all(), self.member, 'read', **self.runtime
            ).values_list('pk', flat=True)
        )
        self.assertEqual(pks, expected)

    def test_anonymous_list_is_empty_without_sql(self):
        view = self._view(paginate_by=None)
        request = self._get(AnonymousUser())
        with self.assertNumQueries(0):
            response = view(request)
        self.assertEqual(list(response.context_data['object_list']), [])


class S4CBVObjectTest(S4FixtureMixin, TestCase):
    def _detail(self, **attrs):
        attrs.setdefault('model', S1Repository)
        attrs.setdefault('object_operation', 'read')
        attrs.setdefault('context', self.context)
        attrs.setdefault('trustee', self.trustee)
        attrs.setdefault('update_url', '/update/')
        attrs.setdefault('delete_url', '/delete/')
        view_class = type(
            'RepoDetail', (AuthorizedObjectMixin, DetailView), attrs,
        )
        return view_class.as_view()

    def _update(self, **attrs):
        attrs.setdefault('model', S1Repository)
        attrs.setdefault('object_operation', 'write')
        attrs.setdefault('fields', ('title',))
        attrs.setdefault('context', self.context)
        attrs.setdefault('trustee', self.trustee)
        attrs.setdefault('template_name', 'trusts/authorized_form.html')
        view_class = type(
            'RepoUpdate', (AuthorizedObjectMixin, UpdateView), attrs,
        )
        return view_class.as_view()

    def _get(self, user):
        request = self.factory.get('/detail/')
        request.user = user
        return request

    def test_detail_granted_is_one_combined_query(self):
        view = self._detail()
        request = self._get(self.member)
        with self.assertNumQueries(1):
            response = view(request, pk=self.repo_a.pk)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data['object'].pk, self.repo_a.pk)
        rendered = response.render()
        self.assertContains(rendered, 'repo-a')
        self.assertContains(rendered, '/update/')
        self.assertContains(rendered, '/delete/')

    def test_detail_unauthorized_is_403_not_404(self):
        view = self._detail()
        request = self._get(self.member)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_b.pk)
        missing_pk = self.repo_a.pk + self.repo_b.pk + self.repo_c.pk + 1000
        with self.assertNumQueries(2):
            with self.assertRaises(Http404):
                view(request, pk=missing_pk)

    def test_missing_pk_is_404_without_sql(self):
        view = self._detail()
        request = self._get(self.member)
        with self.assertNumQueries(0):
            with self.assertRaises(Http404):
                view(request)

    def test_anonymous_existing_is_403_one_existence_query(self):
        view = self._detail()
        request = self._get(AnonymousUser())
        with self.assertNumQueries(1):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)

    def test_inactive_and_unauthenticated_are_403(self):
        view = self._detail()
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

    def test_update_requires_write(self):
        view = self._update()
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.write,
        )
        self.team.bundles.get().operations.add(self.write)
        with self.assertNumQueries(1):
            response = view(request, pk=self.repo_a.pk)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response.render(), 'csrf')

    def test_object_agrees_with_list_queryset(self):
        for repo in (self.repo_a, self.repo_b):
            listed = filter_authorized(
                S1Repository.objects.filter(pk=repo.pk),
                self.member, 'read', **self.runtime,
            ).exists()
            if listed:
                obj = resolve_authorized_object(
                    S1Repository.objects.filter(pk=repo.pk),
                    self.member, 'read', **self.runtime,
                )
                self.assertEqual(obj.pk, repo.pk)
            else:
                with self.assertRaises(PermissionDenied):
                    resolve_authorized_object(
                        S1Repository.objects.filter(pk=repo.pk),
                        self.member, 'read', **self.runtime,
                    )

    def test_unregistered_resource_is_403(self):
        view_class = type('NoteDetail', (AuthorizedObjectMixin, DetailView), dict(
            model=S1UnregisteredNote,
            object_operation='read',
            context=self.context,
            trustee=self.trustee,
        ))
        note = S1UnregisteredNote.objects.create(
            repository=self.repo_a, text='nope',
        )
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view_class.as_view()(request, pk=note.pk)

    def test_callable_operation_is_403(self):
        view = self._detail(object_operation=lambda request: 'read')
        request = self._get(self.member)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)

    def test_is_superuser_does_not_bypass_object_policy(self):
        view = self._detail()
        self.member.is_superuser = True
        request = self._get(self.member)
        self.assertEqual(view(request, pk=self.repo_a.pk).status_code, 200)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_b.pk)
        superuser = User.objects.create_superuser(
            'root', 'root@example.com', 'secret',
        )
        request = self._get(superuser)
        with self.assertRaises(PermissionDenied):
            view(request, pk=self.repo_a.pk)

    def test_unknown_operation_data_is_403_when_resource_exists(self):
        view = self._detail(object_operation='missing')
        request = self._get(self.member)
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                view(request, pk=self.repo_a.pk)


class S4TemplateOverrideTest(S4FixtureMixin, TestCase):
    def test_consumer_template_override_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'trusts'
            dest.mkdir()
            (dest / 'authorized_list.html').write_text('CONSUMER-OVERRIDE')
            templates = dict(settings.TEMPLATES[0])
            templates['DIRS'] = [tmp]
            with override_settings(TEMPLATES=[templates]):
                source = get_template('trusts/authorized_list.html').template.source
                self.assertEqual(source, 'CONSUMER-OVERRIDE')
        self.assertIn(
            'Authorized list',
            get_template('trusts/authorized_list.html').template.source,
        )

    def test_form_and_delete_stubs_render(self):
        form = get_template('trusts/authorized_form.html')
        self.assertIn('form.as_p', form.template.source)
        self.assertIn('csrf_token', form.template.source)
        confirm = get_template('trusts/authorized_confirm_delete.html')
        self.assertIn('Confirm', confirm.template.source)
        self.assertIn('csrf_token', confirm.template.source)
