"""Listed backends OR their own catalogs. A miss is quiet.

Two content apps each have a config and a backend. App B's model is
registered only on B, then on both, and with ``along=`` only inside B.
"""
from contextlib import contextmanager
from unittest import SkipTest

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import run_checks
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils.module_loading import import_string

from tests.core.pair_alpha.backends import PairAlphaBackend
from tests.core.pair_alpha.models import Note, NoteAlso, NoteGrant, Shelf
from tests.core.pair_beta.backends import PairBetaBackend
from tests.core.pair_beta.models import Binder, Page, PageDirect, PageGrant
from tests.support import compiler, push_catalog
from trusts.decorators import authorization_required
from trusts.errors import TrustsConfigurationError
from trusts.models import PermittedUsersManagerMixin


ALPHA = 'tests.core.pair_alpha.backends.PairAlphaBackend'
BETA = 'tests.core.pair_beta.backends.PairBetaBackend'
HOST = 'tests.kernel_host.backends.HostTrustModelBackend'
DOCUMENT = 'tests.myapp.backends.DocumentBackend'
BROKEN_IMPROPER = 'tests.core.test_backend_or._BrokenImproper'
BROKEN_TRUSTS = 'tests.core.test_backend_or._BrokenTrusts'


class _BrokenImproper:
    def __init__(self):
        raise ImproperlyConfigured('improper boom')


class _BrokenTrusts:
    def __init__(self):
        raise TrustsConfigurationError('trusts boom')


def _grant_users():
    """User manager that mixes in the Trusts reverse inquiry."""
    User = get_user_model()

    class GrantUsers(PermittedUsersManagerMixin, User._default_manager.__class__):
        pass

    manager = GrantUsers()
    manager.model = User
    return manager


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type, codename=codename,
        defaults={'name': codename},
    )
    return permission


def _note_catalog(*trusts):
    handle = compiler()
    for trust in trusts:
        handle.register(
            trust=trust, user='user', permission='permission',
            content='shelf__notes',
        )
    return handle


def _page_catalog(trust, *, along=None):
    handle = compiler()
    handle.register(
        trust=trust, user='user', permission='permission',
        content='binder__pages', along=along,
    )
    return handle


@contextmanager
def _listed(alpha, beta):
    restore_alpha = push_catalog(PairAlphaBackend, alpha)
    restore_beta = push_catalog(PairBetaBackend, beta)
    try:
        with override_settings(AUTHENTICATION_BACKENDS=(ALPHA, BETA)):
            yield
    finally:
        restore_alpha()
        restore_beta()


class ListedBackendOrTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not apps.is_installed('tests.core.pair_alpha'):
            raise SkipTest('pair content apps are not installed')

    def setUp(self):
        User = get_user_model()
        self.holder = User.objects.create_user('pair-holder', password='x')
        self.other = User.objects.create_user('pair-other', password='x')
        self.superuser = User.objects.create_superuser(
            'pair-root', password='x', email='pair-root@example.com',
        )
        self.inactive = User.objects.create_user('pair-inactive', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.note_perm = _permission(Note, 'change_note')
        self.page_perm = _permission(Page, 'change_page')
        self.note_code = 'pair_alpha.change_note'
        self.page_code = 'pair_beta.change_page'
        self.shelf = Shelf.objects.create(title='shelf')
        self.note = Note.objects.create(shelf=self.shelf, title='note')
        self.root = Binder.objects.create(title='root')
        self.child = Binder.objects.create(title='child', parent=self.root)
        self.root_page = Page.objects.create(binder=self.root, title='root-page')
        self.child_page = Page.objects.create(binder=self.child, title='child-page')

    def test_only_the_registering_catalog_answers(self):
        NoteGrant.objects.create(
            shelf=self.shelf, user=self.holder, permission=self.note_perm,
        )
        PageGrant.objects.create(
            binder=self.root, user=self.holder, permission=self.page_perm,
        )
        alpha = _note_catalog(NoteGrant)
        beta = _page_catalog(PageGrant, along=('binder__parent', 1))
        with _listed(alpha, beta):
            self._assert_note(allowed=('both', 'alpha'), denied=('beta',))
            self._assert_page(allowed=('both', 'beta'), denied=('alpha',))
            self.assertFalse(self.other.has_perm(self.note_code, self.note))
            self.assertFalse(self.other.has_perm(self.page_code, self.child_page))

    def test_other_backend_denies_quietly(self):
        PageGrant.objects.create(
            binder=self.root, user=self.holder, permission=self.page_perm,
        )
        alpha = compiler()
        beta = _page_catalog(PageGrant)
        with _listed(alpha, beta):
            foreign = self.root_page
            own = PairBetaBackend()
            other = PairAlphaBackend()
            self.assertFalse(other.has_perm(self.holder, self.page_code, foreign))
            self.assertTrue(own.has_perm(self.holder, self.page_code, foreign))
            self.assertTrue(self.holder.has_perms([self.page_code], foreign))
            self.assertFalse(other.has_perm(self.holder, self.note_code, foreign))
            self.assertFalse(own.has_perm(self.holder, self.note_code, foreign))
            self.assertEqual(other.get_all_permissions(self.holder, foreign), set())
            self.assertEqual(
                own.get_all_permissions(self.holder, foreign), {self.page_code},
            )
            self.assertEqual(other.get_group_permissions(self.holder, foreign), set())
            self.assertEqual(own.get_group_permissions(self.holder, foreign), set())
            users = _grant_users()
            self.assertEqual(
                set(users.with_perm(self.page_code, obj=foreign, backend=ALPHA)),
                set(),
            )
            self.assertEqual(
                set(users.with_perm(self.page_code, obj=foreign, backend=BETA)),
                {self.holder},
            )
            self.assertEqual(
                set(foreign.get_permitted_users(self.page_perm, backend=ALPHA)),
                set(),
            )
            self.assertEqual(
                set(foreign.get_permitted_users(self.page_perm, backend=BETA)),
                {self.holder},
            )

    def test_both_catalogs_or_distinct_grant_tables(self):
        NoteGrant.objects.create(
            shelf=self.shelf, user=self.holder, permission=self.note_perm,
        )
        NoteAlso.objects.create(
            shelf=self.shelf, user=self.other, permission=self.note_perm,
        )
        alpha = _note_catalog(NoteGrant)
        beta = _note_catalog(NoteAlso)
        with _listed(alpha, beta):
            both = {self.holder.pk, self.other.pk}
            self.assertEqual(self._user_pks(self.note), both)
            self.assertEqual(
                self._user_pks(self.note, backend=ALPHA), {self.holder.pk},
            )
            self.assertEqual(
                self._user_pks(self.note, backend=BETA), {self.other.pk},
            )
            self.assertEqual(
                set(Note.objects.permitted(self.note_code, self.holder)),
                {self.note},
            )
            self.assertEqual(
                set(Note.objects.permitted(
                    self.note_code, self.holder, backend=BETA,
                )),
                set(),
            )
            self.assertEqual(
                set(Note.objects.permitted(
                    self.note_code, self.other, backend=ALPHA,
                )),
                set(),
            )
            self.assertTrue(self.holder.has_perm(self.note_code, self.note))
            self.assertTrue(self.other.has_perm(self.note_code, self.note))
            self.assertFalse(
                PairAlphaBackend().has_perm(self.other, self.note_code, self.note),
            )
            self.assertFalse(
                PairBetaBackend().has_perm(self.holder, self.note_code, self.note),
            )

    def test_along_stays_inside_the_catalog_that_registered_it(self):
        PageGrant.objects.create(
            binder=self.root, user=self.holder, permission=self.page_perm,
        )
        PageDirect.objects.create(
            binder=self.child, user=self.other, permission=self.page_perm,
        )
        alpha = _page_catalog(PageDirect)
        beta = _page_catalog(PageGrant, along=('binder__parent', 1))
        with _listed(alpha, beta):
            self.assertTrue(self.holder.has_perm(self.page_code, self.child_page))
            self.assertFalse(
                PairAlphaBackend().has_perm(
                    self.holder, self.page_code, self.child_page,
                ),
            )
            self.assertTrue(
                PairBetaBackend().has_perm(
                    self.holder, self.page_code, self.child_page,
                ),
            )
            self.assertEqual(
                set(Page.objects.permitted(self.page_code, self.holder)),
                {self.root_page, self.child_page},
            )
            self.assertEqual(
                set(Page.objects.permitted(
                    self.page_code, self.holder, backend=ALPHA,
                )),
                set(),
            )
            self.assertEqual(
                set(Page.objects.authorized(self.holder, self.page_perm)),
                {self.root_page, self.child_page},
            )
            self.assertEqual(
                set(Page.objects.authorized(
                    self.holder, self.page_perm, backend=ALPHA,
                )),
                set(),
            )
            self.assertEqual(self._binders(backend=ALPHA), set())
            self.assertEqual(self._binders(backend=BETA), {self.root.pk, self.child.pk})
            self.assertEqual(self._binders(), {self.root.pk, self.child.pk})
            self.assertEqual(
                self._user_pks(self.child_page), {self.holder.pk, self.other.pk},
            )
            self.assertEqual(
                self._user_pks(self.child_page, backend=ALPHA), {self.other.pk},
            )
            self.assertEqual(
                self._user_pks(self.child_page, backend=BETA), {self.holder.pk},
            )
            self.assertNotIn(self.holder.pk, self._user_pks(self.root_page, backend=ALPHA))
            self.assertIn(self.holder.pk, self._user_pks(self.root_page, backend=BETA))

    def test_backend_argument_is_a_dotted_path(self):
        NoteGrant.objects.create(
            shelf=self.shelf, user=self.holder, permission=self.note_perm,
        )
        alpha = _note_catalog(NoteGrant)
        beta = compiler()
        with _listed(alpha, beta):
            self.assertEqual(
                set(Note.objects.permitted(
                    self.note_code, self.holder, backend=ALPHA,
                )),
                {self.note},
            )
            with self.assertRaises(TypeError):
                Note.objects.permitted(self.note_code, self.holder, backend=PairAlphaBackend)
            loaded = import_string(ALPHA)()
            self.assertTrue(loaded.has_perm(self.holder, self.note_code, self.note))

    def test_with_perm_ors_catalogs_and_ignores_the_django_flags(self):
        NoteGrant.objects.create(
            shelf=self.shelf, user=self.holder, permission=self.note_perm,
        )
        NoteGrant.objects.create(
            shelf=self.shelf, user=self.inactive, permission=self.note_perm,
        )
        NoteAlso.objects.create(
            shelf=self.shelf, user=self.other, permission=self.note_perm,
        )
        alpha = _note_catalog(NoteGrant)
        beta = _note_catalog(NoteAlso)
        users = _grant_users()
        with _listed(alpha, beta):
            found = set(users.with_perm(
                self.note_code, obj=self.note,
            ).values_list('pk', flat=True))
            self.assertEqual(found, {self.holder.pk, self.other.pk})
            self.assertNotIn(self.superuser.pk, found)
            self.assertNotIn(self.inactive.pk, found)
            inactive_flag = set(users.with_perm(
                self.note_code, is_active=False, include_superusers=True,
                obj=self.note,
            ).values_list('pk', flat=True))
            self.assertEqual(inactive_flag, found)
            alpha_only = set(users.with_perm(
                self.note_code, backend=ALPHA, obj=self.note,
            ).values_list('pk', flat=True))
            self.assertEqual(alpha_only, {self.holder.pk})
            self.assertFalse(users.with_perm(self.note_code).exists())

    def test_unlisted_registrations_raise_from_ready(self):
        import tests.core.pair_alpha as pair_alpha
        from trusts.apps import TrustsConfigMixin

        class Unlisted(TrustsConfigMixin):
            name = 'tests.core.pair_alpha'
            label = 'pair_alpha_unlisted'
            default = False

        config = Unlisted('tests.core.pair_alpha', pair_alpha)
        config.recorder.register(
            trust=NoteGrant, user='user', permission='permission',
            content='shelf',
        )
        with self.assertRaises(TrustsConfigurationError) as caught:
            config.ready()
        message = str(caught.exception)
        self.assertIn(
            'Trusts app pair_alpha_unlisted has registrations but no '
            'AUTHENTICATION_BACKENDS entry resolves to it.',
            message,
        )
        self.assertIn(
            'List a backend whose module lives in this app.', message,
        )

    def test_each_unbuildable_backend_is_e011(self):
        with override_settings(
            AUTHENTICATION_BACKENDS=(HOST, BROKEN_IMPROPER, BROKEN_TRUSTS),
        ):
            messages = run_checks()
        built = [
            message for message in messages
            if getattr(message, 'id', None) == 'trusts.E011'
        ]
        self.assertEqual(
            [message.msg for message in built],
            [
                'Authentication backend %s could not be built: %s' % (
                    BROKEN_IMPROPER, 'improper boom'),
                'Authentication backend %s could not be built: %s' % (
                    BROKEN_TRUSTS, 'trusts boom'),
            ],
        )
        self.assertTrue(all(
            message.hint == 'Fix AUTHENTICATION_BACKENDS so the backend constructs.'
            for message in built
        ))
        self.assertFalse(any(
            getattr(message, 'id', None) == 'trusts.E010'
            and 'could not be built' in message.msg
            for message in messages
        ))

    def test_non_mixin_backend_app_is_e012_once(self):
        outside = 'tests.gh_permissions.backends.OutsideBackend'
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, outside, outside)):
            messages = run_checks()
        mixin = [
            message for message in messages
            if getattr(message, 'id', None) == 'trusts.E012'
        ]
        self.assertEqual(
            [(message.msg, message.obj.label) for message in mixin],
            [('App gh_permissions must extend TrustsConfigMixin.', 'gh_permissions')],
        )
        self.assertEqual(
            mixin[0].hint, 'Extend TrustsConfigMixin on the app config.')
        self.assertFalse(any(
            getattr(message, 'id', None) == 'trusts.E011' and outside in message.msg
            for message in messages
        ))

    def test_unbuildable_and_non_mixin_are_both_reported(self):
        outside = 'tests.gh_permissions.backends.OutsideBackend'
        with override_settings(
            AUTHENTICATION_BACKENDS=(HOST, BROKEN_IMPROPER, outside),
        ):
            messages = run_checks()
        self.assertEqual(
            [message.msg for message in messages
             if getattr(message, 'id', None) == 'trusts.E011'],
            ['Authentication backend %s could not be built: %s' % (
                BROKEN_IMPROPER, 'improper boom')],
        )
        mixin = [
            message for message in messages
            if getattr(message, 'id', None) == 'trusts.E012'
        ]
        self.assertEqual(
            [(message.msg, message.obj.label) for message in mixin],
            [('App gh_permissions must extend TrustsConfigMixin.', 'gh_permissions')],
        )

    def test_each_backend_outside_any_app_is_e012(self):
        import sys
        import types

        from django.contrib.auth.backends import ModelBackend
        from tests.gh_permissions.backends import OutsideBackend
        from trusts.backends import TrustModelBackendMixin

        def loose(name):
            module_name = 'loose_trusts_%s' % name
            module = types.ModuleType(module_name)
            sys.modules[module_name] = module
            cls = type(name, (TrustModelBackendMixin, ModelBackend), {})
            cls.__module__ = module_name
            setattr(module, name, cls)
            return '%s.%s' % (module_name, name), cls

        first, first_cls = loose('LooseOne')
        second, second_cls = loose('LooseTwo')
        wording = (
            'Backend %s is not inside an app whose config extends '
            'TrustsConfigMixin.'
        )
        with self.assertRaises(ImproperlyConfigured) as raised:
            first_cls()
        self.assertEqual(str(raised.exception), wording % first)
        with self.assertRaises(ImproperlyConfigured) as raised:
            OutsideBackend()
        self.assertEqual(
            str(raised.exception),
            'App gh_permissions must extend TrustsConfigMixin.',
        )
        with override_settings(
            AUTHENTICATION_BACKENDS=(HOST, first, first, second),
        ):
            messages = run_checks()
        mixin = [
            message for message in messages
            if getattr(message, 'id', None) == 'trusts.E012'
        ]
        self.assertEqual(
            [(message.msg, message.obj, message.hint) for message in mixin],
            [
                (wording % first, first,
                 'Move the backend into an app whose config extends '
                 'TrustsConfigMixin.'),
                (wording % second, second,
                 'Move the backend into an app whose config extends '
                 'TrustsConfigMixin.'),
            ],
        )
        self.assertFalse(any(
            getattr(message, 'id', None) == 'trusts.E011'
            for message in messages
        ))

    def test_user_queryset_must_be_a_queryset(self):
        from trusts.backends import compile_permitted_users

        with self.assertRaises(TrustsConfigurationError):
            compile_permitted_users(
                self.note, self.note_perm, user_queryset=object())

    def test_no_listed_trusts_backend_is_an_empty_queryset(self):
        from trusts.backends import compile_permitted_users

        with override_settings(AUTHENTICATION_BACKENDS=(
            'django.contrib.auth.backends.ModelBackend',
        )):
            empty = compile_permitted_users(self.note, self.note_perm)
        self.assertEqual(list(empty), [])
        self.assertIs(empty.model, get_user_model())

    def _assert_note(self, *, allowed, denied):
        self._assert_side(
            self.note, self.note_code, self.note_perm, Note,
            self._shelves, allowed, denied,
        )

    def _assert_page(self, *, allowed, denied):
        self._assert_side(
            self.child_page, self.page_code, self.page_perm, Page,
            self._binders, allowed, denied,
        )

    def _assert_side(self, obj, code, perm, model, prefixes, allowed, denied):
        backends = {'alpha': PairAlphaBackend, 'beta': PairBetaBackend}
        paths = {'alpha': ALPHA, 'beta': BETA, 'both': None}
        self.assertTrue(self.holder.has_perm(code, obj))
        for name in denied:
            self.assertFalse(backends[name]().has_perm(self.holder, code, obj))
            self.assertEqual(set(model.objects.permitted(
                code, self.holder, backend=paths[name],
            )), set())
            self.assertEqual(set(model.objects.authorized(
                self.holder, perm, backend=paths[name],
            )), set())
            self.assertEqual(prefixes(backend=paths[name]), set())
            self.assertNotIn(self.holder, set(self._users(obj, backend=paths[name])))
            guard = authorization_required(model, code, backend=paths[name])(
                lambda request, pk: 'ok',
            )
            with self.assertRaises(PermissionDenied):
                guard(_request(self.holder), pk=obj.pk)
        for name in allowed:
            backend = None if name == 'both' else backends[name]
            path = paths[name]
            if backend is not None:
                self.assertTrue(backend().has_perm(self.holder, code, obj))
            self.assertEqual(set(model.objects.permitted(
                code, self.holder, backend=path,
            )), {obj} if obj is self.note else {self.root_page, self.child_page})
            self.assertIn(obj, set(model.objects.authorized(
                self.holder, perm, backend=path,
            )))
            self.assertIn(self.holder, set(self._users(obj, backend=path)))
            self.assertTrue(prefixes(backend=path))
            guard = authorization_required(model, code, backend=path)(
                lambda request, pk: 'ok',
            )
            self.assertEqual(guard(_request(self.holder), pk=obj.pk), 'ok')

    def _users(self, obj, backend=None):
        perm = self.note_perm if obj is self.note else self.page_perm
        return obj.get_permitted_users(perm, backend=backend)

    def _user_pks(self, obj, backend=None):
        return set(self._users(obj, backend=backend).values_list('pk', flat=True))

    def _shelves(self, backend=None):
        from trusts.decorators import filter_by_permitted_content
        return set(filter_by_permitted_content(
            Shelf.objects.all(), self.holder, self.note_perm,
            content=Note, backend=backend,
        ).values_list('pk', flat=True))

    def _binders(self, backend=None):
        from trusts.decorators import filter_by_permitted_content
        return set(filter_by_permitted_content(
            Binder.objects.all(), self.holder, self.page_perm,
            content=Page, backend=backend,
        ).values_list('pk', flat=True))
