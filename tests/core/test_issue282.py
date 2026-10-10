"""Along reverse inquiry, policy SQL, and terminal combinations (#282).

Reverse permitted-users must equal the forward object check, including
the terminal condition and active-principal rule. The policy lock records
the public walk and renders the same recursive SQL. ``group=`` and a
terminal many-to-many ``permission=`` stay on the forward path.
"""

from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import isolate_apps

from tests.backends import HostTrustModelBackend
from tests.core import KernelHostRequiredMixin
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
from trusts.core import BackendHandle, PlanQueryCompiler, TrustsRegistry
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import PermittedManager, PermittedUsersManagerMixin, PermittedUsersMixin


HOST = 'tests.backends.HostTrustModelBackend'
_APPS = (
    'tests',
    'tests.kernel_host',
    'tests.myapp',
    'django.contrib.auth',
    'django.contrib.contenttypes',
)


class PlainUserManager(PermittedUsersManagerMixin, type(get_user_model().objects)):
    pass


class Issue282SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue282', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue282', PAIR_KERNEL_SUITE)


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


@contextmanager
def _installed(registry):
    config = implementation_for_path(HOST)
    saved = dict(config.registries)
    config.registries[HOST] = registry
    try:
        yield
    finally:
        config.registries.clear()
        config.registries.update(saved)


def _handle(registry):
    return BackendHandle(
        path=HOST, registry=registry, compiler=PlanQueryCompiler(),
    )


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _code(permission):
    return '%s.%s' % (permission.content_type.app_label, permission.codename)


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


def _agree(test, content, perm, users):
    code = _code(perm) if not isinstance(perm, str) else perm
    expected = {user.pk for user in users if user.has_perm(code, content)}
    with test.assertNumQueries(1):
        found = _pks(content.get_permitted_users(perm))
    test.assertEqual(found, expected)
    manager = PlainUserManager()
    manager.model = get_user_model()
    manager.name = 'objects'
    test.assertEqual(_pks(manager.permitted(content, perm)), found)
    return found


def _assert_lock(test, handle, specs, *, group=False):
    document = _load_policy_sql_document(
        render_policy_sql_bytes(handles=[handle]),
    )
    test.assertEqual(document['schema_version'], 1)
    content = document['backends'][0]['contents'][0]
    trusts = content['trusts']
    test.assertEqual(
        [row['along'] for row in trusts],
        list(specs),
    )
    for row, spec in zip(trusts, specs):
        test.assertIn(
            '__along_%s_%s_%s' % (spec['path'], spec['shape'], spec['bound']),
            row['id'],
        )
    keys = (
        'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
    )
    if group:
        keys = keys + ('get_group_permissions',)
    else:
        test.assertNotIn('get_group_permissions', content)
    for key in keys:
        block = content[key]
        test.assertGreaterEqual(
            block['sql'].upper().count('WITH RECURSIVE'), len(specs),
        )
        for spec in specs:
            test.assertIn({'const': spec['bound']}, block['params'])
    users = content['get_permitted_users']
    test.assertIn({'bind': 'content.id'}, users['params'])
    test.assertIn({'bind': 'permission.id'}, users['params'])
    test.assertIn({'const': True}, users['params'])
    test.assertIn('WITH RECURSIVE', users['sql'].upper())
    if len(specs) > 1:
        test.assertIn(' OR ', users['sql'])
        test.assertTrue(all(row.get('or_group') is True for row in trusts))
    return content


def _contribute_m2m(field, model):
    # isolate_apps does not finish M2M contribution onto an
    # already-prepared auth model. The forward collection is still the
    # permission hop under test.
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(model, field.remote_field)


def _users():
    User = get_user_model()
    alice = User.objects.create_user('alice-282', password='x')
    bob = User.objects.create_user('bob-282', password='x')
    inactive = User.objects.create_user('inactive-282', password='x')
    inactive.is_active = False
    inactive.save(update_fields=['is_active'])
    superuser = User.objects.create_superuser(
        'super-282', email='super-282@example.com', password='x',
    )
    return alice, bob, inactive, superuser


def _place_models(suffix, *, extra=None):
    class Place(PermittedUsersMixin, models.Model):
        parent = models.ForeignKey(
            'self', null=True, related_name='children',
            on_delete=models.CASCADE,
        )
        objects = PermittedManager()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue282_%s_place' % suffix

    class Grant(models.Model):
        place = models.ForeignKey(Place, on_delete=models.CASCADE)
        user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        if extra == 'holder':
            holder = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE,
            )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue282_%s_grant' % suffix

    return Place, Grant


@isolate_apps(*_APPS)
class Issue282AlongAgreementTest(KernelHostRequiredMixin, TransactionTestCase):
    def test_reverse_matches_forward_at_bound_and_one_past(self):
        Place, Grant = _place_models('bound')
        with _tables(Place, Grant):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            code = _code(read)
            root = Place.objects.create()
            near = Place.objects.create(parent=root)
            at_bound = Place.objects.create(parent=near)
            past = Place.objects.create(parent=at_bound)
            Grant.objects.create(place=root, user=alice, permission=read)
            Grant.objects.create(place=root, user=inactive, permission=read)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=Grant,
                user='user',
                permission='permission',
                content='place',
                along=('place__parent', 2),
            )
            spec = {'path': 'place__parent', 'shape': 'S', 'bound': 2}
            _assert_lock(self, handle, [spec])
            people = (alice, bob, inactive, superuser)
            backend = HostTrustModelBackend()
            with _installed(registry):
                for node, alice_allowed in (
                    (root, True), (near, True), (at_bound, True), (past, False),
                ):
                    found = _agree(self, node, read, people)
                    self.assertEqual(alice.pk in found, alice_allowed)
                    self.assertNotIn(bob.pk, found)
                    self.assertNotIn(inactive.pk, found)
                    self.assertIn(superuser.pk, found)
                    _agree(self, node, code, people)
                allowed = set(Place.objects.permitted(code, alice))
                self.assertEqual(allowed, {root, near, at_bound})
                self.assertIn(code, backend.get_all_permissions(alice, at_bound))
                self.assertNotIn(code, backend.get_all_permissions(alice, past))
                self.assertIn(
                    '("auth_user"."id")',
                    str(at_bound.get_permitted_users(read).query),
                )

    def test_cycle_agrees_and_terminates(self):
        Place, Grant = _place_models('cycle')
        with _tables(Place, Grant):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            left = Place.objects.create()
            right = Place.objects.create(parent=left)
            left.parent = right
            left.save(update_fields=['parent'])
            outsider = Place.objects.create()
            Grant.objects.create(place=left, user=alice, permission=read)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=Grant,
                user='user',
                permission='permission',
                content='place',
                along=('place__parent', 4),
            )
            _assert_lock(self, handle, [{
                'path': 'place__parent', 'shape': 'S', 'bound': 4,
            }])
            people = (alice, bob, inactive, superuser)
            with _installed(registry):
                for node in (left, right):
                    found = _agree(self, node, read, people)
                    self.assertIn(alice.pk, found)
                missed = _agree(self, outsider, read, people)
                self.assertNotIn(alice.pk, missed)
                self.assertIn(superuser.pk, missed)

    def test_failing_condition_denies_and_passing_condition_reaches_descendants(self):
        Place, Grant = _place_models('cond', extra='holder')
        with _tables(Place, Grant):
            alice, bob, _inactive, superuser = _users()
            User = get_user_model()
            cara = User.objects.create_user('cara-282', password='x')
            read = _permission(Place, 'read_place')
            root = Place.objects.create()
            child = Place.objects.create(parent=root)
            Grant.objects.create(
                place=root, user=alice, holder=alice, permission=read,
            )
            Grant.objects.create(
                place=root, user=cara, holder=bob, permission=read,
            )
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=Grant,
                user='user',
                permission='permission',
                content='place',
                condition=lambda row: row.user == row.holder,
                along=('place__parent', 2),
            )
            _assert_lock(self, handle, [{
                'path': 'place__parent', 'shape': 'S', 'bound': 2,
            }])
            people = (alice, bob, cara, superuser)
            with _installed(registry):
                for node in (root, child):
                    found = _agree(self, node, read, people)
                    self.assertIn(alice.pk, found)
                    self.assertNotIn(cara.pk, found)
                    self.assertNotIn(bob.pk, found)
                sql = str(child.get_permitted_users(read).query)
                self.assertIn('WITH RECURSIVE', sql.upper())
                self.assertIn('holder_id', sql)
                self.assertIn('parent_id', sql)

    def test_inactive_principal_with_a_reaching_grant_is_excluded(self):
        Place, Grant = _place_models('inactive')
        with _tables(Place, Grant):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            root = Place.objects.create()
            child = Place.objects.create(parent=root)
            Grant.objects.create(place=root, user=inactive, permission=read)
            Grant.objects.create(place=root, user=alice, permission=read)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=Grant,
                user='user',
                permission='permission',
                content='place',
                along=('place__parent', 1),
            )
            _assert_lock(self, handle, [{
                'path': 'place__parent', 'shape': 'S', 'bound': 1,
            }])
            people = (alice, bob, inactive, superuser)
            with _installed(registry):
                found = _agree(self, child, read, people)
                self.assertIn(alice.pk, found)
                self.assertNotIn(inactive.pk, found)
                self.assertNotIn(bob.pk, found)
                self.assertFalse(inactive.has_perm(_code(read), child))
                self.assertTrue(alice.has_perm(_code(read), child))

    def test_two_along_registrations_on_one_content_model_are_ored(self):
        Place, North = _place_models('north')

        class South(models.Model):
            place = models.ForeignKey(Place, on_delete=models.CASCADE)
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_south_grant'

        with _tables(Place, North, South):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            root = Place.objects.create()
            mid = Place.objects.create(parent=root)
            leaf = Place.objects.create(parent=mid)
            past = Place.objects.create(parent=leaf)
            # S walks descendants of the grant. C walks ancestors.
            # A grant on mid reaches one hop each way and stops at past.
            North.objects.create(place=mid, user=alice, permission=read)
            South.objects.create(place=mid, user=bob, permission=read)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=North,
                user='user',
                permission='permission',
                content='place',
                along=('place__parent', 1),
            )
            handle.register(
                trust=South,
                user='user',
                permission='permission',
                content='place',
                along=('place__children', 1),
            )
            _assert_lock(self, handle, [
                {'path': 'place__parent', 'shape': 'S', 'bound': 1},
                {'path': 'place__children', 'shape': 'C', 'bound': 1},
            ])
            people = (alice, bob, inactive, superuser)
            with _installed(registry):
                on_leaf = _agree(self, leaf, read, people)
                on_root = _agree(self, root, read, people)
                on_mid = _agree(self, mid, read, people)
                on_past = _agree(self, past, read, people)
                self.assertIn(alice.pk, on_leaf)
                self.assertNotIn(bob.pk, on_leaf)
                self.assertIn(bob.pk, on_root)
                self.assertNotIn(alice.pk, on_root)
                self.assertIn(alice.pk, on_mid)
                self.assertIn(bob.pk, on_mid)
                self.assertNotIn(alice.pk, on_past)
                self.assertNotIn(bob.pk, on_past)
                self.assertNotIn(inactive.pk, on_mid)

    def test_group_along_reaches_the_bound_on_forward_and_reverse_paths(self):
        Place, _grant = _place_models('group')

        class GroupGrant(models.Model):
            place = models.ForeignKey(Place, on_delete=models.CASCADE)
            group = models.ForeignKey(Group, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_group_grant'

        with _tables(Place, GroupGrant):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            code = _code(read)
            editors = Group.objects.create(name='editors-282')
            editors.permissions.add(read)
            editors.user_set.add(alice, inactive)
            root = Place.objects.create()
            child = Place.objects.create(parent=root)
            past = Place.objects.create(parent=child)
            GroupGrant.objects.create(place=root, group=editors)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=GroupGrant,
                user='group__user',
                group='group',
                content='place',
                along=('place__parent', 1),
            )
            content = _assert_lock(self, handle, [{
                'path': 'place__parent', 'shape': 'S', 'bound': 1,
            }], group=True)
            self.assertEqual(content['trusts'][0]['group']['path'], 'group')
            self.assertIn(
                'WITH RECURSIVE',
                content['get_group_permissions']['sql'].upper(),
            )
            people = (alice, bob, inactive, superuser)
            backend = HostTrustModelBackend()
            with _installed(registry):
                found = _agree(self, child, read, people)
                self.assertIn(alice.pk, found)
                self.assertNotIn(bob.pk, found)
                self.assertNotIn(inactive.pk, found)
                past_found = _agree(self, past, read, people)
                self.assertNotIn(alice.pk, past_found)
                self.assertEqual(
                    backend.get_group_permissions(alice, child), {code},
                )
                self.assertEqual(
                    backend.get_group_permissions(alice, past), set(),
                )
                self.assertEqual(
                    backend.get_group_permissions(bob, child), set(),
                )
                self.assertEqual(
                    set(Place.objects.permitted(code, alice)), {root, child},
                )

    def test_terminal_m2m_permission_along_reaches_on_the_forward_path(self):
        Place, _grant = _place_models('m2m')

        class Access(models.Model):
            place = models.ForeignKey(Place, on_delete=models.CASCADE)
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE,
            )
            permissions = models.ManyToManyField(
                Permission, related_name='+', blank=True,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'issue282_m2m_access'

        _contribute_m2m(Access._meta.get_field('permissions'), Permission)
        with _tables(Place, Access):
            alice, bob, inactive, superuser = _users()
            read = _permission(Place, 'read_place')
            other = _permission(Place, 'change_place')
            code = _code(read)
            root = Place.objects.create()
            child = Place.objects.create(parent=root)
            past = Place.objects.create(parent=child)
            allowed = Access.objects.create(place=root, user=alice)
            allowed.permissions.add(read)
            denied = Access.objects.create(place=root, user=bob)
            denied.permissions.add(other)
            quiet = Access.objects.create(place=root, user=inactive)
            quiet.permissions.add(read)
            registry = TrustsRegistry()
            handle = _handle(registry)
            handle.register(
                trust=Access,
                user='user',
                permission='permissions',
                content='place',
                along=('place__parent', 1),
            )
            _assert_lock(self, handle, [{
                'path': 'place__parent', 'shape': 'S', 'bound': 1,
            }])
            people = (alice, bob, inactive, superuser)
            backend = HostTrustModelBackend()
            with _installed(registry):
                found = _agree(self, child, read, people)
                self.assertIn(alice.pk, found)
                self.assertNotIn(bob.pk, found)
                self.assertNotIn(inactive.pk, found)
                past_found = _agree(self, past, read, people)
                self.assertNotIn(alice.pk, past_found)
                self.assertIn(code, backend.get_all_permissions(alice, child))
                self.assertNotIn(code, backend.get_all_permissions(alice, past))
                self.assertNotIn(
                    code, backend.get_all_permissions(bob, child),
                )
                self.assertEqual(
                    backend.get_group_permissions(alice, child), set(),
                )
                self.assertEqual(
                    set(Place.objects.permitted(code, alice)), {root, child},
                )
