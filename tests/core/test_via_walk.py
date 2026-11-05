"""User-side ``via=`` walk. One portable recursive statement.

The walk includes the starting row. The bound is steps past it.
``via=("team__subgroups", n)`` walks to parent teams. ``along=`` on
``team__parent`` walks to child teams. A failing member is left out
and the walk continues. Reset reuses the ``along=`` stop.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.support import (
    built_catalog,
    compiler,
    published_class_catalog,
    render_configured_policy,
    scoped_permitted_content,
)
from trusts.backends import TrustModelBackendMixin
from trusts.compile.graph import Along, Ref
from trusts.decorators import authorization_required, filter_by_permitted_content
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)


class _ViaBackend(TrustModelBackendMixin, ModelBackend):
    pass


@contextmanager
def _listed(handle):
    with published_class_catalog(_ViaBackend, handle):
        with override_settings(
            AUTHENTICATION_BACKENDS=('tests.core.test_via_walk._ViaBackend',),
        ):
            yield


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


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaRegistrationTest(SimpleTestCase):
    """``register()`` rejects a walk SQL cannot express."""

    def setUp(self):
        super().setUp()

        class Note(models.Model):
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            content_object = GenericForeignKey()
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Badge(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Flag(models.Model):
            name = models.CharField(max_length=20)
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class WideBase(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Wide(WideBase):

            class Meta:
                app_label = 'trusts_tests'

        class HeldBase(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Team(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            members = models.ManyToManyField(
                get_user_model(), related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            reset_inheritance = models.BooleanField(null=True)
            rank = models.IntegerField(null=True)
            title = models.CharField(max_length=20)
            badge = models.OneToOneField(
                Badge, null=True, related_name='owner',
                on_delete=models.CASCADE,
            )
            flags = models.ManyToManyField(Flag, related_name='teams')
            wide = models.ManyToManyField(Wide, related_name='teams')
            notes = GenericRelation(Note)

            class Meta:
                app_label = 'trusts_tests'

        class Link(models.Model):
            parent = models.ForeignKey(
                Team, related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Team, related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Held(HeldBase):
            parent = models.ForeignKey(
                Team, related_name='held_children', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Team, related_name='held_parents', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Policy(models.Model):
            team = models.ForeignKey(
                Team, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Portrait(models.Model):
            team = models.OneToOneField(
                Team, related_name='portrait', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Job(models.Model):
            team = models.ForeignKey(
                Team, related_name='jobs', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class Org(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            lead = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class Bridge(models.Model):
            org = models.ForeignKey(
                Org, related_name='bridges', on_delete=models.CASCADE,
            )
            delegate_org = models.ForeignKey(
                Org, related_name='+', on_delete=models.CASCADE,
            )
            sponsor_org = models.ForeignKey(
                Org, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        self.Grant = Grant
        self.Bridge = Bridge

    def test_terminal_membership_is_accepted(self):
        handle = compiler(path='tests.core.via-register-ok')
        handle.register(
            trust=self.Grant,
            user='team__members',
            group='auth_group',
            content='team__jobs',
            via=('team__subgroups', 8),
        )

    def test_rejections(self):
        cases = (
            (
                'shape',
                dict(via='team__subgroups'),
                'pair',
            ),
            (
                'bound-bool',
                dict(via=('team__subgroups', True)),
                'bound',
            ),
            (
                'bound-low',
                dict(via=('team__subgroups', 0)),
                'bound',
            ),
            (
                'bound-high',
                dict(via=('team__subgroups', 65)),
                'bound',
            ),
            (
                'neither',
                dict(via=('auth_group', 1)),
                'walk-site prefix',
            ),
            (
                'fk-edge',
                dict(via=('team__auth_group', 1)),
                'walk-site model',
            ),
            (
                'reset-type',
                dict(via=('team__subgroups', 2, 'rank')),
                'BooleanField',
            ),
            (
                'reset-missing',
                dict(via=('team__subgroups', 2, 'missing')),
                'missing field',
            ),
        )
        for name, extra, fragment in cases:
            with self.subTest(name):
                handle = compiler(path='tests.core.via-register-%s' % name)
                with self.assertRaisesRegex(TrustsConfigurationError, fragment):
                    handle.register(
                        trust=self.Grant,
                        user='team__members',
                        group='auth_group',
                        content='team__jobs',
                        **extra,
                    )

    def test_delegation_must_match_exactly_one_side(self):
        both = compiler(path='tests.core.via-register-both')
        with self.assertRaisesRegex(TrustsConfigurationError, 'exactly one'):
            both.register(
                trust=self.Bridge,
                delegate='delegate_org__lead',
                sponsor='delegate_org__lead',
                content='org',
                via=('delegate_org__subgroups', 4),
            )
        neither = compiler(path='tests.core.via-register-neither')
        with self.assertRaisesRegex(TrustsConfigurationError, 'exactly one'):
            neither.register(
                trust=self.Bridge,
                delegate='delegate_org__lead',
                sponsor='sponsor_org__lead',
                content='org',
                via=('org__subgroups', 4),
            )

    def _reject(self, label, via, fragment, exc=TrustsConfigurationError,
                **paths):
        handle = compiler(path='tests.core.via-rej-%s' % label)
        mode = paths.pop('mode', 'grant')
        with self.assertRaisesRegex(exc, fragment):
            if mode == 'delegation':
                handle.register(
                    trust=self.Bridge,
                    delegate=paths.get('delegate', 'delegate_org__lead'),
                    sponsor=paths.get('sponsor', 'sponsor_org__lead'),
                    content='org',
                    via=via,
                )
            else:
                handle.register(
                    trust=self.Grant,
                    user=paths.get('user', 'team__members'),
                    group='auth_group',
                    content='team__jobs',
                    via=via,
                )

    def test_rejects_a_value_that_is_not_a_pair_or_triple(self):
        cases = (
            ('string', 'team__subgroups', 'pair'),
            ('empty', (), 'pair'),
            ('one', ('team__subgroups',), 'pair'),
            ('four', ('team__subgroups', 2, 'reset_inheritance', 1), 'triple'),
            (
                'along',
                Along(Ref(self.Grant, ('team', 'subgroups')), 2),
                'Along',
            ),
            ('ref', Ref(self.Grant, ('team', 'subgroups')), 'Ref'),
        )
        for label, via, fragment in cases:
            exc = (
                TypeError if label in ('along', 'ref')
                else TrustsConfigurationError
            )
            with self.subTest(label):
                self._reject(label, via, fragment, exc)

    def test_rejects_a_bound_outside_1_to_64(self):
        cases = (
            ('bool', True, 'integer'),
            ('zero', 0, 'integer'),
            ('high', 65, 'integer'),
            ('negative', -1, 'integer'),
            ('float', 1.5, 'integer'),
            ('text', '4', 'integer'),
        )
        for label, bound, fragment in cases:
            with self.subTest(label):
                self._reject(label, ('team__subgroups', bound), fragment)

    def test_rejects_a_path_that_is_not_exactly_one_walk_site(self):
        cases = (
            ('neither', ('auth_group', 1), 'walk-site prefix', {}),
            (
                'both',
                ('delegate_org__subgroups', 4),
                'exactly one',
                {'mode': 'delegation', 'sponsor': 'delegate_org__lead'},
            ),
            (
                'delegation-neither',
                ('org__subgroups', 4),
                'exactly one',
                {'mode': 'delegation'},
            ),
            ('no-edge', ('team__members', 1), 'no edge hop', {}),
        )
        for label, via, fragment, extra in cases:
            with self.subTest(label):
                self._reject(label, via, fragment, **extra)

    def test_rejects_an_edge_the_walk_cannot_express(self):
        cases = (
            ('other-model', ('team__auth_group', 1), 'walk-site model'),
            ('m2m', ('team__flags', 1), 'exactly one relation hop'),
            ('generic', ('team__notes', 1), 'walk-site model'),
        )
        for label, via, fragment in cases:
            with self.subTest(label):
                self._reject(label, via, fragment)

    def test_rejects_an_identity_that_is_not_one_supported_column(self):
        User = get_user_model()

        class FloatSite(models.Model):
            ident = models.FloatField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='ident', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class FloatGrant(models.Model):
            site = models.ForeignKey(
                FloatSite, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class TextSite(models.Model):
            code = models.CharField(max_length=36, unique=True)
            parent = models.ForeignKey(
                'self', to_field='code', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class TextGrant(models.Model):
            site = models.ForeignKey(TextSite, on_delete=models.CASCADE)
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class UuidSite(models.Model):
            ident = models.UUIDField(unique=True)
            slug = models.SlugField(unique=True)
            parent = models.ForeignKey(
                'self', to_field='slug', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class UuidGrant(models.Model):
            site = models.ForeignKey(
                UuidSite, to_field='ident', on_delete=models.CASCADE,
            )
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        cases = (
            ('float', FloatGrant, 'site__parent', 'integer, text, or UUID'),
            ('text-versus-pk', TextGrant, 'site__parent', 'must match'),
            ('uuid-versus-text', UuidGrant, 'site__parent', 'must match'),
        )
        for label, grant, path, fragment in cases:
            with self.subTest(label):
                handle = compiler(path='tests.core.via-ident-%s' % label)
                with self.assertRaisesRegex(TrustsConfigurationError, fragment):
                    handle.register(
                        trust=grant,
                        user='site',
                        permission='permission',
                        content='site',
                        via=(path, 4),
                    )

    def test_rejects_a_step_toward_the_user_that_user_equals_rejects(self):
        cases = (
            ('m2m-middle', 'team__flags__name', 'multi-valued'),
            ('generic', 'team__notes', 'generic foreign key'),
            ('reverse', 'team__policies', 'reverse'),
            ('scalar', 'team__title', 'scalar'),
        )
        for label, user, fragment in cases:
            with self.subTest(label):
                self._reject(
                    'suffix-%s' % label,
                    ('team__subgroups', 2),
                    fragment,
                    user=user,
                )

    def test_rejects_a_reset_field_along_equals_rejects(self):
        cases = (
            (('team__subgroups', 4, 'portrait__reset_inheritance'), 'reverse one-to-one'),
            (('team__subgroups', 4, 'parent__reset_inheritance'), 'forward foreign key'),
            (('team__subgroups', 4, 'badge__reset_inheritance'), 'forward foreign key'),
            (
                ('team__subgroups', 4, 'parent__subgroups__reset_inheritance'),
                'one relation',
            ),
            (('team__subgroups', 4, 'notes__reset_inheritance'), 'generic relation'),
            (('team__subgroups', 4, 'title'), 'BooleanField'),
            (('team__subgroups', 4, 'rank'), 'BooleanField'),
            (('team__subgroups', 4, 'flags__name'), 'BooleanField'),
            (('team__subgroups', 4, 'missing'), 'missing'),
            (('team__subgroups', 4, None), 'field path'),
            (('team__subgroups', 4, ''), 'field path'),
            (
                ('team__parent_links__parent', 4, 'parent_links__parent'),
                'BooleanField',
            ),
            (
                (
                    'team__held_parents__parent', 4,
                    'held_parents__reset_inheritance',
                ),
                'parent-table',
            ),
            (('team__subgroups', 4, 'wide__reset_inheritance'), 'parent-table'),
        )
        for via, fragment in cases:
            with self.subTest(via=via):
                self._reject('reset-%s' % (via[2],), via, fragment)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaWalkTest(TransactionTestCase):
    """The six inquiries agree on one group walk, including reset."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Team(models.Model):
            name = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            members = models.ManyToManyField(User, related_name='+')
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_team'

        members = Team._meta.get_field('members')
        if not hasattr(members, 'm2m_field_name'):
            members.contribute_to_related_class(User, members.remote_field)

        class JobQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Job(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            team = models.ForeignKey(
                Team, related_name='jobs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(JobQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_job'

            def __str__(self):
                return self.name

        class Grant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_grant'

        self.User = User
        self.Team = Team
        self.Job = Job
        self.Grant = Grant
        cm = _tables(Team, Job, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Job, 'change_job')
        self.code = 'trusts_tests.change_job'
        self.teams = {}
        self.jobs = {}
        for name, parent, reset in (
            ('root', None, None),
            ('org', 'root', None),
            ('backend', 'org', None),
            ('api', 'backend', None),
        ):
            self._team(name, parent, reset)
        self.alice = self._user('via-alice')
        self.bob = self._user('via-bob')
        self.cara = self._user('via-cara')
        self.dave = self._user('via-dave')
        self.rita = self._user('via-rita')
        self.teams['org'].members.add(self.alice, self.dave)
        self.teams['backend'].members.add(self.bob)
        self.teams['api'].members.add(self.cara)
        self.teams['root'].members.add(self.rita)

    def _user(self, name):
        return self.User.objects.create_user(name, password='x')

    def _team(self, name, parent, reset):
        group = Group.objects.create(name='via-%s' % name)
        group.permissions.add(self.change)
        team = self.Team.objects.create(
            name=name,
            parent=self.teams.get(parent),
            auth_group=group,
            reset_inheritance=reset,
        )
        self.teams[name] = team
        self.jobs[name] = self.Job.objects.create(name=name, team=team)
        return team

    def _grant(self, name):
        team = self.teams[name]
        return self.Grant.objects.create(team=team, auth_group=team.auth_group)

    def _open(self, name, via, along=None):
        handle = compiler(path='tests.core.via-walk.%s' % name)
        kwargs = {}
        if along is not None:
            kwargs['along'] = along
        handle.register(
            trust=self.Grant,
            user='team__members',
            group='auth_group',
            content='team__jobs',
            via=via,
            **kwargs,
        )
        return handle

    def _titles(self, handle, user):
        jobs = list(self.Job.objects.all())
        catalog = built_catalog(handle)
        with _listed(handle):
            permitted = set(self.Job.objects.permitted(
                self.code, user,
            ).values_list('name', flat=True))
            authorized = set(self.Job.objects.authorized(
                user, self.change,
            ).values_list('name', flat=True))
            held = set()
            holders = set()
            grouped = set()
            complete = set()
            for job in jobs:
                if user.has_perm(self.code, job):
                    held.add(job.name)
                if job.get_permitted_users(self.change).filter(pk=user.pk).exists():
                    holders.add(job.name)
                if self.code in user.get_all_permissions(job):
                    complete.add(job.name)
                if self.code in user.get_group_permissions(job):
                    grouped.add(job.name)
        self.assertEqual(permitted, held)
        self.assertEqual(authorized, held)
        self.assertEqual(holders, held)
        self.assertEqual(complete, held)
        self.assertEqual(grouped, held)
        listed = scoped_permitted_content(
            self.Team.objects.all(), user, self.change,
            content=self.Job, registry=catalog,
        )
        teams = set(listed.values_list('name', flat=True))
        self.assertEqual(teams, {
            self.jobs[name].team.name for name in held
        })
        return held

    def test_cases(self):
        self.alice.is_active = False
        self.alice.save(update_fields=['is_active'])
        grant = self._grant('api')
        handle = self._open('members', ('team__subgroups', 8))
        with self.subTest('inactive member dropped, walk continues'):
            self.assertEqual(self._titles(handle, self.alice), set())
            self.assertEqual(self._titles(handle, self.dave), {'api'})
            self.assertEqual(self._titles(handle, self.bob), {'api'})
            self.assertEqual(self._titles(handle, self.cara), {'api'})
        grant.delete()
        self.alice.is_active = True
        self.alice.save(update_fields=['is_active'])

        self._grant('api')
        cycled = self.teams['org']
        cycled.parent = self.teams['api']
        cycled.save(update_fields=['parent'])
        handle = self._open('cycle', ('team__subgroups', 8))
        with self.subTest('cycle adds no user'):
            looped = {}
            for user in (self.alice, self.bob, self.cara, self.rita):
                looped[user.pk] = self._titles(handle, user)
                reached = self.jobs['api'].get_permitted_users(self.change)
                with _listed(handle):
                    rows = list(reached.values_list('pk', flat=True))
                self.assertEqual(len(rows), len(set(rows)))
            cycled.parent = None
            cycled.save(update_fields=['parent'])
            opened = self._open('cycle-open', ('team__subgroups', 8))
            for user in (self.alice, self.bob, self.cara, self.rita):
                self.assertEqual(self._titles(opened, user), looped[user.pk])
            cycled.parent = self.teams['root']
            cycled.save(update_fields=['parent'])
        self.Grant.objects.all().delete()

        self._grant('backend')
        wide = self._open('bound-wide', ('team__subgroups', 8), ('team__parent', 8))
        short = self._open('bound-short', ('team__subgroups', 1), ('team__parent', 1))
        with self.subTest('along plus via'):
            self.assertEqual(self._titles(wide, self.alice), {'backend', 'api'})
            self.assertEqual(self._titles(wide, self.bob), {'backend', 'api'})
            self.assertEqual(self._titles(wide, self.cara), set())
            self.assertEqual(self._titles(wide, self.rita), {'backend', 'api'})
        with self.subTest('bound'):
            self.assertEqual(self._titles(short, self.alice), {'backend', 'api'})
            self.assertEqual(self._titles(short, self.rita), set())
            self.assertEqual(self._titles(short, self.bob), {'backend', 'api'})
        self.Grant.objects.all().delete()

        self.teams['backend'].reset_inheritance = True
        self.teams['backend'].save(update_fields=['reset_inheritance'])
        stopped = self._open('reset', ('team__subgroups', 8, 'reset_inheritance'))
        self._grant('api')
        with self.subTest('reset stops before the flagged team'):
            self.assertEqual(self._titles(stopped, self.cara), {'api'})
            self.assertEqual(self._titles(stopped, self.bob), set())
        self.Grant.objects.all().delete()
        self._grant('backend')
        with self.subTest('reset grant on the stop continues past it'):
            self.assertEqual(self._titles(stopped, self.bob), {'backend'})
            self.assertEqual(self._titles(stopped, self.alice), {'backend'})
            self.assertEqual(self._titles(stopped, self.rita), {'backend'})
            self.assertEqual(self._titles(stopped, self.cara), set())

    def test_lockfile_records_bound_and_reset(self):
        handle = self._open('lock', ('team__subgroups', 4, 'reset_inheritance'))
        text = render_configured_policy(handle).decode()
        self.assertIn('$via_bound', text)
        self.assertIn('via:', text)
        self.assertIn('reset: "reset_inheritance"', text)
        self.assertIn('__via_team__subgroups_C_4', text)
        self.assertIn('__reset_reset_inheritance', text)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaDelegationTest(TransactionTestCase):
    """``via=`` walks the delegate side or the sponsor side, not both."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Org(models.Model):
            name = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            lead = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_org'

        class DeskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Desk(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            org = models.ForeignKey(
                Org, related_name='desks', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(DeskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_desk'

        class DeskGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            org = models.ForeignKey(Org, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_desk_grant'

        class Bridge(models.Model):
            org = models.ForeignKey(
                Org, related_name='bridges', on_delete=models.CASCADE,
            )
            delegate_org = models.ForeignKey(
                Org, related_name='+', on_delete=models.CASCADE,
            )
            sponsor_org = models.ForeignKey(
                Org, related_name='+', on_delete=models.CASCADE,
            )
            actor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_bridge'

        self.User = User
        self.Org = Org
        self.Desk = Desk
        self.DeskGrant = DeskGrant
        self.Bridge = Bridge
        cm = _tables(Org, Desk, DeskGrant, Bridge)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Desk, 'change_desk')
        self.code = 'trusts_tests.change_desk'
        self.root_lead = User.objects.create_user('via-root-lead', password='x')
        self.mid_lead = User.objects.create_user('via-mid-lead', password='x')
        self.leaf_lead = User.objects.create_user('via-leaf-lead', password='x')
        self.actor = User.objects.create_user('via-actor', password='x')
        self.root = Org.objects.create(name='root', lead=self.root_lead)
        self.mid = Org.objects.create(
            name='mid', parent=self.root, lead=self.mid_lead,
        )
        self.leaf = Org.objects.create(
            name='leaf', parent=self.mid, lead=self.leaf_lead,
        )
        self.desk = Desk.objects.create(name='desk', org=self.leaf)

    def _ordinary(self, user):
        return self.DeskGrant.objects.create(
            user=user, permission=self.change, org=self.leaf,
        )

    def _allowed(self, handle, user):
        catalog = built_catalog(handle)
        with _listed(handle):
            permitted = set(self.Desk.objects.permitted(
                self.code, user,
            ).values_list('name', flat=True))
            has = user.has_perm(self.code, self.desk)
            held = self.code in user.get_all_permissions(self.desk)
            grouped = self.code in user.get_group_permissions(self.desk)
            reached = self.desk.get_permitted_users(
                self.change,
            ).filter(pk=user.pk).exists()
            authorized = set(self.Desk.objects.authorized(
                user, self.change,
            ).values_list('name', flat=True))
        orgs = set(scoped_permitted_content(
            self.Org.objects.all(), user, self.change,
            content=self.Desk, registry=catalog,
        ).values_list('name', flat=True))
        allowed = 'desk' in permitted
        self.assertEqual(has, allowed)
        self.assertEqual(held, allowed)
        self.assertEqual(reached, allowed)
        self.assertEqual('desk' in authorized, allowed)
        self.assertIs(grouped, False)
        if allowed:
            self.assertEqual(orgs, {'leaf'})
        else:
            self.assertEqual(orgs, set())
        return allowed

    def test_delegate_walk_reaches_ancestor_leads(self):
        self._ordinary(self.mid_lead)
        self.Bridge.objects.create(
            org=self.leaf, delegate_org=self.leaf, sponsor_org=self.mid,
            actor=self.actor,
        )
        wide = compiler(path='tests.core.via-delegate-wide')
        wide.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='org__desks',
        )
        wide.register(
            trust=self.Bridge,
            delegate='delegate_org__lead',
            sponsor='sponsor_org__lead',
            content='org__desks',
            via=('delegate_org__subgroups', 8),
        )
        short = compiler(path='tests.core.via-delegate-short')
        short.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='org__desks',
        )
        short.register(
            trust=self.Bridge,
            delegate='delegate_org__lead',
            sponsor='sponsor_org__lead',
            content='org__desks',
            via=('delegate_org__subgroups', 1),
        )
        self.assertIs(self._allowed(wide, self.leaf_lead), True)
        self.assertIs(self._allowed(wide, self.mid_lead), True)
        self.assertIs(self._allowed(wide, self.root_lead), True)
        self.assertIs(self._allowed(wide, self.actor), False)
        self.assertIs(self._allowed(short, self.leaf_lead), True)
        self.assertIs(self._allowed(short, self.mid_lead), True)
        self.assertIs(self._allowed(short, self.root_lead), False)

    def test_sponsor_walk_keeps_going_past_an_inactive_lead(self):
        self.leaf_lead.is_active = False
        self.leaf_lead.save(update_fields=['is_active'])
        self._ordinary(self.leaf_lead)
        self._ordinary(self.mid_lead)
        self.Bridge.objects.create(
            org=self.leaf, delegate_org=self.leaf, sponsor_org=self.leaf,
            actor=self.actor,
        )
        handle = compiler(path='tests.core.via-sponsor')
        handle.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='org__desks',
        )
        handle.register(
            trust=self.Bridge,
            delegate='actor',
            sponsor='sponsor_org__lead',
            content='org__desks',
            via=('sponsor_org__subgroups', 8),
        )
        self.assertIs(self._allowed(handle, self.actor), True)
        self.assertIs(self._allowed(handle, self.leaf_lead), False)
        self.DeskGrant.objects.filter(user=self.mid_lead).delete()
        self.assertIs(self._allowed(handle, self.actor), False)

    def test_sponsor_walk_meets_the_ordinary_walk(self):
        """Both walks run, and the actor needs a user who is on each."""
        _attach_manager(self, self.User)
        self.leaf_lead.via_manager = self.mid_lead
        self.leaf_lead.save(update_fields=['via_manager'])
        self._ordinary(self.leaf_lead)
        self.Bridge.objects.create(
            org=self.leaf, delegate_org=self.leaf, sponsor_org=self.leaf,
            actor=self.actor,
        )
        handle = compiler(path='tests.core.via-meet')
        handle.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='org__desks',
            via=('user__via_manager', 8),
        )
        handle.register(
            trust=self.Bridge,
            delegate='actor',
            sponsor='sponsor_org__lead',
            content='org__desks',
            via=('sponsor_org__subgroups', 8),
        )
        self.assertIs(self._allowed(handle, self.actor), True)
        stranger = self.User.objects.create_user('via-stranger', password='x')
        self.assertIs(self._allowed(handle, stranger), False)


def _chain_models(table, job_name):
    """Team, job, and grant classes for one agreement tree."""
    User = get_user_model()

    class Team(models.Model):
        name = models.CharField(max_length=20)
        parent = models.ForeignKey(
            'self', null=True, related_name='subgroups',
            on_delete=models.CASCADE,
        )
        members = models.ManyToManyField(User, related_name='+')
        auth_group = models.ForeignKey(
            Group, on_delete=models.CASCADE, related_name='+',
        )
        reset_inheritance = models.BooleanField(null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = table + '_team'

    members = Team._meta.get_field('members')
    if not hasattr(members, 'm2m_field_name'):
        members.contribute_to_related_class(User, members.remote_field)

    class JobQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
        pass

    class Job(PermittedUsersMixin, models.Model):
        name = models.CharField(max_length=20)
        team = models.ForeignKey(
            Team, related_name='jobs', on_delete=models.CASCADE,
        )
        objects = models.Manager.from_queryset(JobQuerySet)()

        class Meta:
            app_label = 'trusts_tests'
            db_table = table + '_job'

        def __str__(self):
            return self.name

    class Grant(models.Model):
        team = models.ForeignKey(Team, on_delete=models.CASCADE)
        auth_group = models.ForeignKey(
            Group, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = table + '_grant'

    Job.__name__ = job_name
    return Team, Job, Grant


class _AgreementMixin(object):
    """Six inquiries, and ``authorized``, name the same jobs."""

    def _held(self, handle, user):
        jobs = list(self.Job.objects.all())
        catalog = built_catalog(handle)
        with _listed(handle):
            permitted = set(self.Job.objects.permitted(
                self.code, user,
            ).values_list('name', flat=True))
            authorized = set(self.Job.objects.authorized(
                user, self.change,
            ).values_list('name', flat=True))
            held, holders, grouped, complete = set(), set(), set(), set()
            for job in jobs:
                if user.has_perm(self.code, job):
                    held.add(job.name)
                if job.get_permitted_users(self.change).filter(pk=user.pk).exists():
                    holders.add(job.name)
                if self.code in user.get_all_permissions(job):
                    complete.add(job.name)
                if self.code in user.get_group_permissions(job):
                    grouped.add(job.name)
        self.assertEqual(permitted, held)
        self.assertEqual(authorized, held)
        self.assertEqual(holders, held)
        self.assertEqual(complete, held)
        self.assertEqual(grouped, held)
        listed = scoped_permitted_content(
            self.Team.objects.all(), user, self.change,
            content=self.Job, registry=catalog,
        )
        self.assertEqual(set(listed.values_list('name', flat=True)), held)
        return held

    def _open(self, name, via, along=None):
        prefix = getattr(self, 'path_prefix', 'via-agree')
        handle = compiler(path='tests.core.%s.%s' % (prefix, name))
        kwargs = {}
        if along is not None:
            kwargs['along'] = along
        handle.register(
            trust=self.Grant,
            user='team__members',
            group='auth_group',
            content='team__jobs',
            via=via,
            **kwargs,
        )
        return handle

    def _grant(self, name):
        team = self.teams[name]
        return self.Grant.objects.create(team=team, auth_group=team.auth_group)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaAgreementTest(_AgreementMixin, TransactionTestCase):
    """Bounds, cycles, both walks, and an inactive member."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.Team, self.Job, self.Grant = _chain_models('via_agree', 'AgreeJob')
        cm = _tables(self.Team, self.Job, self.Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(self.Job, 'change_agreejob')
        self.code = 'trusts_tests.change_agreejob'
        self.teams = {}
        self.users = {}
        parent = {
            'org': 'root', 'backend': 'org', 'api': 'backend', 'edge': 'api',
        }
        for name in ('root', 'org', 'backend', 'api', 'edge', 'side'):
            group = Group.objects.create(name='agree-%s' % name)
            group.permissions.add(self.change)
            self.teams[name] = self.Team.objects.create(
                name=name,
                parent=self.teams.get(parent.get(name)),
                auth_group=group,
            )
            self.Job.objects.create(name=name, team=self.teams[name])
        membership = {
            'root': ('rita',),
            'org': ('alice', 'dave'),
            'backend': ('bob',),
            'api': ('cara', 'carl'),
            'edge': ('ned',),
            'side': ('sue',),
        }
        for team_name, names in membership.items():
            for name in names:
                user = User.objects.create_user('agree-%s' % name, password='x')
                self.users[name] = user
                self.teams[team_name].members.add(user)

    def test_bound_includes_that_depth_and_excludes_the_next(self):
        holder = {
            'root': 'rita', 'org': 'alice', 'backend': 'bob',
            'api': 'cara', 'edge': 'ned',
        }
        down = (
            (1, ('root', 'org'), ('backend',)),
            (2, ('root', 'org', 'backend'), ('api',)),
            (3, ('root', 'org', 'backend', 'api'), ('edge',)),
        )
        for bound, reached, missed in down:
            with self.subTest(direction='down', bound=bound):
                self.Grant.objects.all().delete()
                self._grant('root')
                handle = self._open('down-%s' % bound, ('team__parent', bound))
                for name in reached:
                    self.assertEqual(
                        self._held(handle, self.users[holder[name]]), {'root'}, name,
                    )
                for name in missed:
                    self.assertEqual(
                        self._held(handle, self.users[holder[name]]), set(), name,
                    )
        up = (
            (1, ('edge', 'api'), ('backend',)),
            (2, ('edge', 'api', 'backend'), ('org',)),
            (3, ('edge', 'api', 'backend', 'org'), ('root',)),
        )
        for bound, reached, missed in up:
            with self.subTest(direction='up', bound=bound):
                self.Grant.objects.all().delete()
                self._grant('edge')
                handle = self._open('up-%s' % bound, ('team__subgroups', bound))
                for name in reached:
                    self.assertEqual(
                        self._held(handle, self.users[holder[name]]), {'edge'}, name,
                    )
                for name in missed:
                    self.assertEqual(
                        self._held(handle, self.users[holder[name]]), set(), name,
                    )

    def test_cycle_adds_no_user(self):
        self._grant('root')
        opened = self._open('cycle-open', ('team__parent', 8))
        expected = {
            name: self._held(opened, user)
            for name, user in self.users.items()
        }
        self.teams['root'].parent = self.teams['edge']
        self.teams['root'].save(update_fields=['parent'])
        cycled = self._open('cycle', ('team__parent', 8))
        for name, user in self.users.items():
            with self.subTest(name):
                self.assertEqual(self._held(cycled, user), expected[name])
        with _listed(cycled):
            rows = list(self.Job.objects.get(name='root').get_permitted_users(
                self.change,
            ).values_list('pk', flat=True))
        self.assertEqual(len(rows), len(set(rows)))
        self.assertIn(self.users['ned'].pk, rows)
        self.assertNotIn(self.users['sue'].pk, rows)

    def test_along_and_via_keep_separate_bounds(self):
        self._grant('backend')
        via_depth = {'bob': 0, 'alice': 1, 'dave': 1, 'rita': 2}
        along_depth = {'backend': 0, 'api': 1, 'edge': 2}
        for via_bound in (1, 2):
            for along_bound in (1, 2):
                with self.subTest(via=via_bound, along=along_bound):
                    handle = self._open(
                        'both-%s-%s' % (via_bound, along_bound),
                        ('team__subgroups', via_bound),
                        ('team__parent', along_bound),
                    )
                    for name, user in self.users.items():
                        depth = via_depth.get(name)
                        if depth is None or depth > via_bound:
                            want = set()
                        else:
                            want = {
                                job for job, job_depth in along_depth.items()
                                if job_depth <= along_bound
                            }
                        self.assertEqual(self._held(handle, user), want, name)

    def test_inactive_member_is_dropped_and_the_walk_continues(self):
        self._grant('api')
        handle = self._open('idle', ('team__subgroups', 8))
        reached = ('cara', 'carl', 'bob', 'alice', 'dave', 'rita')
        for name in ('cara', 'bob', 'alice', 'rita'):
            with self.subTest(inactive=name):
                user = self.users[name]
                user.is_active = False
                user.save(update_fields=['is_active'])
                try:
                    for other in reached:
                        want = set() if other == name else {'api'}
                        self.assertEqual(
                            self._held(handle, self.users[other]), want, other,
                        )
                    self.assertEqual(self._held(handle, self.users['ned']), set())
                finally:
                    user.is_active = True
                    user.save(update_fields=['is_active'])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaResetPlacementTest(_AgreementMixin, TransactionTestCase):
    """The four reset placements cut every path into the stop."""

    path_prefix = 'via-cut'

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Flag(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_flag'

        class Team(models.Model):
            name = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            members = models.ManyToManyField(User, related_name='+')
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            reset_inheritance = models.BooleanField(null=True)
            flags = models.ManyToManyField(Flag, related_name='teams')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_team'

        members = Team._meta.get_field('members')
        if not hasattr(members, 'm2m_field_name'):
            members.contribute_to_related_class(User, members.remote_field)

        class Link(models.Model):
            parent = models.ForeignKey(
                Team, related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Team, related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_link'

        class Policy(models.Model):
            team = models.ForeignKey(
                Team, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_policy'

        class JobQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Job(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            team = models.ForeignKey(
                Team, related_name='jobs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(JobQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_job'

        class Grant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_cut_grant'

        self.Team, self.Job, self.Grant = Team, Job, Grant
        self.Flag, self.Link, self.Policy = Flag, Link, Policy
        cm = _tables(Flag, Team, Link, Policy, Job, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Job, 'change_cutjob')
        self.code = 'trusts_tests.change_cutjob'
        self.teams = {}
        self.users = {}
        for name, parent in (('A', None), ('B', 'A'), ('C', 'B'), ('D', None)):
            group = Group.objects.create(name='cut-%s' % name)
            group.permissions.add(self.change)
            self.teams[name] = Team.objects.create(
                name=name, parent=self.teams.get(parent), auth_group=group,
            )
            Job.objects.create(name=name, team=self.teams[name])
            user = User.objects.create_user('cut-%s' % name, password='x')
            self.users[name] = user
            self.teams[name].members.add(user)
        self.links = {
            'AB': Link.objects.create(
                parent=self.teams['A'], child=self.teams['B'],
            ),
            'DB': Link.objects.create(
                parent=self.teams['D'], child=self.teams['B'],
            ),
            'BC': Link.objects.create(
                parent=self.teams['B'], child=self.teams['C'],
            ),
        }

    def _clear_cuts(self):
        self.Team.objects.update(reset_inheritance=None)
        self.Link.objects.update(reset_inheritance=None)
        self.Flag.objects.all().delete()
        self.Policy.objects.all().delete()
        self.Grant.objects.all().delete()

    def _arm_node(self):
        team = self.teams['B']
        team.reset_inheritance = True
        team.save(update_fields=['reset_inheritance'])

    def _arm_false(self):
        team = self.teams['B']
        team.reset_inheritance = False
        team.save(update_fields=['reset_inheritance'])

    def _arm_flags(self):
        true = self.Flag.objects.create(reset_inheritance=True)
        false = self.Flag.objects.create(reset_inheritance=False)
        self.teams['B'].flags.add(false, true)
        self.teams['C'].flags.add(false)

    def _arm_policies(self):
        self.Policy.objects.create(
            team=self.teams['B'], reset_inheritance=False,
        )
        self.Policy.objects.create(
            team=self.teams['B'], reset_inheritance=True,
        )
        self.Policy.objects.create(
            team=self.teams['C'], reset_inheritance=None,
        )

    def _arm_edge(self):
        self.links['AB'].reset_inheritance = True
        self.links['AB'].save(update_fields=['reset_inheritance'])
        self.links['BC'].reset_inheritance = False
        self.links['BC'].save(update_fields=['reset_inheritance'])

    def test_four_placements_cut_every_path_into_the_stop(self):
        stopped = (
            ('A', {'A': {'A'}, 'B': set(), 'C': set(), 'D': set()}),
            ('B', {'A': set(), 'B': {'B'}, 'C': {'B'}, 'D': set()}),
        )
        opened = (
            ('A', {'A': {'A'}, 'B': {'A'}, 'C': {'A'}, 'D': set()}),
        )
        edge_stopped = (
            ('A', {'A': {'A'}, 'B': set(), 'C': set(), 'D': set()}),
            ('D', {'D': {'D'}, 'B': {'D'}, 'C': {'D'}, 'A': set()}),
            ('B', {'B': {'B'}, 'C': {'B'}, 'A': set(), 'D': set()}),
        )
        every_path = (
            ('A', {'A': {'A'}, 'B': set(), 'C': set(), 'D': set()}),
            ('D', {'D': {'D'}, 'B': set(), 'C': set(), 'A': set()}),
            ('B', {'B': {'B'}, 'C': {'B'}, 'A': set(), 'D': set()}),
        )
        cases = (
            ('node', ('team__parent', 8, 'reset_inheritance'), self._arm_node, stopped),
            ('node-null', ('team__parent', 8, 'reset_inheritance'), lambda: None, opened),
            ('node-false', ('team__parent', 8, 'reset_inheritance'), self._arm_false, opened),
            ('m2m', ('team__parent', 8, 'flags__reset_inheritance'), self._arm_flags, stopped),
            (
                'reverse-fk',
                ('team__parent', 8, 'policies__reset_inheritance'),
                self._arm_policies,
                stopped,
            ),
            (
                'edge',
                (
                    'team__parent_links__parent', 8,
                    'parent_links__reset_inheritance',
                ),
                self._arm_edge,
                edge_stopped,
            ),
            (
                'node-every-path',
                ('team__parent_links__parent', 8, 'reset_inheritance'),
                self._arm_node,
                every_path,
            ),
        )
        for label, via, arm, expects in cases:
            with self.subTest(label):
                self._clear_cuts()
                arm()
                handle = self._open(label, via)
                for grant_name, checks in expects:
                    self._grant(grant_name)
                    for user_name, want in checks.items():
                        self.assertEqual(
                            self._held(handle, self.users[user_name]),
                            set(want),
                            '%s grant %s' % (user_name, grant_name),
                        )
                    self.Grant.objects.all().delete()


def _drop_manager_column(user_model):
    """Drop the test column without rebuilding auth's many-to-many tables."""
    table = user_model._meta.db_table
    column = 'via_manager_id'
    with connection.cursor() as cursor:
        present = {
            item.name
            for item in connection.introspection.get_table_description(
                cursor, table,
            )
        }
        if column not in present:
            return
        cursor.execute(
            'ALTER TABLE %s DROP COLUMN %s' % (
                connection.ops.quote_name(table),
                connection.ops.quote_name(column),
            )
        )


def _forget_manager(user_model, field):
    meta = user_model._meta
    if field in meta.local_fields:
        meta.local_fields.remove(field)
    meta._expire_cache()
    if hasattr(user_model, field.name):
        delattr(user_model, field.name)
    accessor = field.remote_field.get_accessor_name()
    if hasattr(user_model, accessor):
        delattr(user_model, accessor)


def _attach_manager(test, user_model):
    """Self-FK on the real user table for this test, then drop it."""
    _drop_manager_column(user_model)
    field = models.ForeignKey(
        'self', null=True, blank=True, related_name='via_reports',
        on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
    )
    user_model.add_to_class('via_manager', field)
    stored = user_model._meta.get_field('via_manager')
    try:
        with connection.schema_editor() as editor:
            editor.add_field(user_model, stored)
    except Exception:
        _forget_manager(user_model, stored)
        raise

    def detach():
        try:
            _drop_manager_column(user_model)
        finally:
            _forget_manager(user_model, stored)

    test.addCleanup(detach)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaUserStopTest(TransactionTestCase):
    """A failing user stops that path. A group walk does not."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_stop_folder'

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='tasks', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_stop_task'

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_stop_seat'

        class DeskGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_stop_desk_grant'

        class Bridge(models.Model):
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_stop_bridge'

        self.User = User
        self.Folder, self.Task = Folder, Task
        self.Seat, self.DeskGrant, self.Bridge = Seat, DeskGrant, Bridge
        cm = _tables(Folder, Task, Seat, DeskGrant, Bridge)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Task, 'change_stoptask')
        self.code = 'trusts_tests.change_stoptask'
        self.people = {}
        for name in ('ada', 'ben', 'cy', 'dee', 'eve', 'zed'):
            self.people[name] = User.objects.create_user(
                'via-%s' % name, password='x',
            )
        ada, ben, cy, dee, eve = (
            self.people[name] for name in ('ada', 'ben', 'cy', 'dee', 'eve')
        )
        ben.via_manager = ada
        ben.is_active = False
        ben.save()
        cy.via_manager = ben
        cy.save()
        dee.via_manager = ada
        dee.save()
        eve.via_manager = dee
        eve.save()
        self.folder = Folder.objects.create(name='folder')
        self.task = Task.objects.create(name='task', folder=self.folder)
        self.group = Group.objects.create(name='via-stop')
        self.group.permissions.add(self.change)
        self.seat = Seat.objects.create(
            holder=ada, auth_group=self.group, folder=self.folder,
        )

    def _sees(self, handle, user, *, group=True, skip=False):
        flags = {'skip_is_active': True} if skip else {}
        catalog = built_catalog(handle)
        backend = _ViaBackend()
        with _listed(handle):
            permitted = set(self.Task.objects.permitted(
                self.code, user, **flags,
            ).values_list('name', flat=True))
            authorized = set(self.Task.objects.authorized(
                user, self.change, **flags,
            ).values_list('name', flat=True))
            if skip:
                has = backend.has_perm(user, self.code, self.task, **flags)
                complete = self.code in backend.get_all_permissions(
                    user, self.task, **flags,
                )
                grouped = self.code in backend.get_group_permissions(
                    user, self.task, **flags,
                )
            else:
                has = user.has_perm(self.code, self.task)
                complete = self.code in user.get_all_permissions(self.task)
                grouped = self.code in user.get_group_permissions(self.task)
            reached = self.task.get_permitted_users(
                self.change, **flags,
            ).filter(pk=user.pk).exists()
        folders = set(scoped_permitted_content(
            self.Folder.objects.all(), user, self.change,
            content=self.Task, registry=catalog, **flags,
        ).values_list('name', flat=True))
        allowed = self.task.name in permitted
        self.assertEqual(authorized, permitted)
        self.assertEqual(has, allowed)
        self.assertEqual(complete, allowed)
        self.assertEqual(reached, allowed)
        if group:
            self.assertEqual(grouped, allowed)
        else:
            self.assertIs(grouped, False)
        self.assertEqual(folders, {self.folder.name} if allowed else set())
        return allowed

    def _seat(self, name, path, bound, condition=None):
        handle = compiler(path='tests.core.via-user.%s' % name)
        if condition is not None:
            handle.set_user_condition('called', condition)
        handle.register(
            trust=self.Seat,
            user='holder',
            group='auth_group',
            content='folder__tasks',
            via=(path, bound),
        )
        return handle

    def test_failing_user_stops_the_path(self):
        wide = self._seat('wide', 'holder__via_manager', 8)
        short = self._seat('short', 'holder__via_manager', 1)
        self.assertIs(self._sees(wide, self.people['ada']), True)
        self.assertIs(self._sees(wide, self.people['dee']), True)
        self.assertIs(self._sees(wide, self.people['eve']), True)
        self.assertIs(self._sees(wide, self.people['ben']), False)
        self.assertIs(self._sees(wide, self.people['cy']), False)
        self.assertIs(self._sees(wide, self.people['zed']), False)
        self.assertIs(self._sees(short, self.people['dee']), True)
        self.assertIs(self._sees(short, self.people['eve']), False)
        ben = self.people['ben']
        ben.is_active = True
        ben.save(update_fields=['is_active'])
        try:
            self.assertIs(self._sees(wide, ben), True)
            self.assertIs(self._sees(wide, self.people['cy']), True)
        finally:
            ben.is_active = False
            ben.save(update_fields=['is_active'])
        self.assertIs(self._sees(wide, ben, skip=True), True)
        self.assertIs(self._sees(wide, self.people['cy'], skip=True), True)
        ada = self.people['ada']
        ada.is_active = False
        ada.save(update_fields=['is_active'])
        try:
            for name in ('ada', 'ben', 'cy', 'dee', 'eve'):
                self.assertIs(self._sees(wide, self.people[name]), False)
        finally:
            ada.is_active = True
            ada.save(update_fields=['is_active'])
        named = self._seat(
            'named', 'holder__via_manager', 8,
            lambda user: user.username == 'via-ada',
        )
        self.assertIs(self._sees(named, ada), True)
        self.assertIs(self._sees(named, self.people['dee']), False)
        self.assertIs(self._sees(named, self.people['eve']), False)

    def test_upward_failing_user_stops_before_the_ancestor(self):
        self.seat.holder = self.people['cy']
        self.seat.save(update_fields=['holder'])
        handle = self._seat('up', 'holder__via_reports', 8)
        self.assertIs(self._sees(handle, self.people['cy']), True)
        self.assertIs(self._sees(handle, self.people['ben']), False)
        self.assertIs(self._sees(handle, self.people['ada']), False)
        ben = self.people['ben']
        ben.is_active = True
        ben.save(update_fields=['is_active'])
        try:
            self.assertIs(self._sees(handle, ben), True)
            self.assertIs(self._sees(handle, self.people['ada']), True)
        finally:
            ben.is_active = False
            ben.save(update_fields=['is_active'])

    def test_delegate_user_walk_stops_at_a_failing_user(self):
        ada = self.people['ada']
        self.DeskGrant.objects.create(
            user=ada, permission=self.change, folder=self.folder,
        )
        self.Bridge.objects.create(
            folder=self.folder, delegate=ada, sponsor=ada,
        )
        handle = compiler(path='tests.core.via-user-delegate')
        handle.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='folder__tasks',
        )
        handle.register(
            trust=self.Bridge,
            delegate='delegate',
            sponsor='sponsor',
            content='folder__tasks',
            via=('delegate__via_manager', 8),
        )
        self.assertIs(self._sees(handle, ada, group=False), True)
        self.assertIs(self._sees(handle, self.people['dee'], group=False), True)
        self.assertIs(self._sees(handle, self.people['eve'], group=False), True)
        self.assertIs(self._sees(handle, self.people['ben'], group=False), False)
        self.assertIs(self._sees(handle, self.people['cy'], group=False), False)
        self.assertIs(self._sees(handle, self.people['zed'], group=False), False)
        ada.is_active = False
        ada.save(update_fields=['is_active'])
        try:
            self.assertIs(self._sees(handle, self.people['dee'], group=False), False)
        finally:
            ada.is_active = True
            ada.save(update_fields=['is_active'])

    def test_sponsor_user_walk_stops_at_a_failing_user(self):
        ada = self.people['ada']
        zed = self.people['zed']
        self.Bridge.objects.create(
            folder=self.folder, delegate=zed, sponsor=ada,
        )
        handle = compiler(path='tests.core.via-user-sponsor')
        handle.register(
            trust=self.DeskGrant,
            user='user',
            permission='permission',
            content='folder__tasks',
        )
        handle.register(
            trust=self.Bridge,
            delegate='delegate',
            sponsor='sponsor',
            content='folder__tasks',
            via=('sponsor__via_manager', 8),
        )
        grant = self.DeskGrant.objects.create(
            user=self.people['dee'], permission=self.change, folder=self.folder,
        )
        self.assertIs(self._sees(handle, zed, group=False), True)
        grant.user = self.people['cy']
        grant.save(update_fields=['user'])
        self.assertIs(self._sees(handle, zed, group=False), False)
        grant.user = self.people['eve']
        grant.save(update_fields=['user'])
        self.assertIs(self._sees(handle, zed, group=False), True)
        grant.user = self.people['ben']
        grant.save(update_fields=['user'])
        self.assertIs(self._sees(handle, zed, group=False), False)
        grant.user = self.people['dee']
        grant.save(update_fields=['user'])
        ada.is_active = False
        ada.save(update_fields=['is_active'])
        try:
            self.assertIs(self._sees(handle, zed, group=False), False)
        finally:
            ada.is_active = True
            ada.save(update_fields=['is_active'])


def _add_user_column(test, model, name, field):
    """Add one column for this test, then drop it."""
    model.add_to_class(name, field)
    stored = model._meta.get_field(name)
    try:
        with connection.schema_editor() as editor:
            editor.add_field(model, stored)
    except Exception:
        _forget_field(model, stored)
        raise

    def detach():
        try:
            try:
                _drop_column(model, stored.column)
            except Exception:
                with connection.schema_editor() as editor:
                    editor.remove_field(model, stored)
        finally:
            _forget_field(model, stored)

    test.addCleanup(detach)
    return stored


def _drop_column(model, column):
    table = model._meta.db_table
    quote = connection.ops.quote_name
    with connection.cursor() as cursor:
        present = {
            item.name
            for item in connection.introspection.get_table_description(
                cursor, table,
            )
        }
        if column not in present:
            return
        cursor.execute(
            'ALTER TABLE %s DROP COLUMN %s' % (quote(table), quote(column))
        )


def _bind_m2m(model, name, related):
    """Finish an isolated many-to-many so ``.add()`` can see its columns."""
    field = model._meta.get_field(name)
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(related, field.remote_field)


def _forget_field(model, field):
    meta = model._meta
    if field in meta.local_fields:
        meta.local_fields.remove(field)
    meta._expire_cache()
    if hasattr(model, field.name):
        delattr(model, field.name)
    remote = getattr(field, 'remote_field', None)
    if remote is None:
        return
    accessor = remote.get_accessor_name()
    if hasattr(model, accessor):
        delattr(model, accessor)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaHopFilterTest(TransactionTestCase):
    """Selected filters and null comparisons on a walked user."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        _add_user_column(
            self, User, 'via_nick',
            models.CharField(max_length=20, null=True),
        )
        _add_user_column(
            self, User, 'via_other',
            models.CharField(max_length=20, null=True),
        )
        _add_user_column(
            self, User, 'via_reset',
            models.BooleanField(null=True),
        )
        self.User = User
        self.people = {}
        for name in ('ada', 'ben', 'cy', 'dee', 'eve'):
            self.people[name] = User.objects.create_user(
                'hop-%s' % name, password='x',
            )
        ada, ben, cy, dee, eve = (
            self.people[name] for name in ('ada', 'ben', 'cy', 'dee', 'eve')
        )
        ben.via_manager = ada
        ben.save()
        cy.via_manager = ben
        cy.save()
        dee.via_manager = ada
        dee.save()
        eve.via_manager = dee
        eve.save()

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_task'

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_seat'

        class Crew(models.Model):
            name = models.CharField(max_length=20, unique=True)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            members = models.ManyToManyField(User, related_name='+')
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_crew'

        class CrewGrant(models.Model):
            crew = models.ForeignKey(Crew, on_delete=models.CASCADE)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_crew_grant'

        self.Task, self.Seat = Task, Seat
        _bind_m2m(Crew, 'members', User)
        self.Crew, self.CrewGrant = Crew, CrewGrant
        cm = _tables(Task, Seat, Crew, CrewGrant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Task, 'change_hoptask')
        self.code = 'trusts_tests.change_hoptask'
        self.task = Task.objects.create(name='task')
        self.group = Group.objects.create(name='via-hop')
        self.group.permissions.add(self.change)
        self.seat = Seat.objects.create(
            holder=ada, auth_group=self.group, task=self.task,
        )

    def _activate(self):
        self.User.objects.filter(username__startswith='hop-').update(is_active=True)

    def _bundle(self, handle, user, *, filtered):
        code = '%s:kept' % self.code if filtered else self.code
        conditions = ('kept',) if filtered else ()
        users = code if filtered else self.change
        catalog = built_catalog(handle)
        with _listed(handle):
            permitted = self.task.name in set(
                self.Task.objects.permitted(
                    self.code, user, conditions=conditions,
                ).values_list('name', flat=True)
            )
            has = user.has_perm(code, self.task)
            reached = self.task.get_permitted_users(users).filter(
                pk=user.pk,
            ).exists()
            complete = self.code in user.get_all_permissions(self.task)
            grouped = self.code in user.get_group_permissions(self.task)
            authorized = self.task.name in set(
                self.Task.objects.authorized(
                    user, self.change,
                ).values_list('name', flat=True)
            )
        folders = self.task.name in set(
            scoped_permitted_content(
                self.Task.objects.all(), user, self.change,
                content=self.Task, registry=catalog,
            ).values_list('name', flat=True)
        )
        return {
            'has': has,
            'permitted': permitted,
            'reached': reached,
            'complete': complete,
            'grouped': grouped,
            'authorized': authorized,
            'folders': folders,
        }

    def _expect(self, handle, user, *, selected, plain, group=True):
        asked = self._bundle(handle, user, filtered=True)
        for key in ('has', 'permitted', 'reached'):
            self.assertEqual(asked[key], selected, key)
        bare = self._bundle(handle, user, filtered=False)
        for key in ('complete', 'grouped', 'authorized'):
            if key == 'grouped' and not group:
                self.assertIs(bare[key], False)
            else:
                self.assertEqual(bare[key], plain, key)
        for key in ('has', 'permitted', 'reached', 'complete', 'authorized'):
            self.assertEqual(bare[key], plain, 'bare %s' % key)

    def _seat(self, name, predicate, via):
        handle = compiler(path='tests.core.via-hop.%s' % name)
        handle.add_named_filter(self.Task, 'kept', predicate)
        handle.register(
            trust=self.Seat,
            user='holder',
            group='auth_group',
            content='task',
            via=via,
        )
        return handle

    def test_named_filter_stops_a_failing_user_and_not_a_group(self):
        self._activate()
        kept = lambda user, permission, content: user.username != 'hop-ben'
        handle = self._seat('user', kept, ('holder__via_manager', 8))
        reached = ('ada', 'dee', 'eve')
        stopped = ('ben', 'cy')
        for name in reached:
            with self.subTest(user=name, walk='user'):
                self._expect(handle, self.people[name], selected=True, plain=True)
        for name in stopped:
            with self.subTest(user=name, walk='user'):
                self._expect(
                    handle, self.people[name], selected=False, plain=True,
                )
        seed = self._seat(
            'seed',
            lambda user, permission, content: user.username != 'hop-ada',
            ('holder__via_manager', 8),
        )
        for name in ('ada', 'ben', 'cy', 'dee', 'eve'):
            with self.subTest(user=name, walk='seed'):
                self._expect(
                    seed, self.people[name], selected=False, plain=True,
                )
        leaf = self._seat(
            'leaf',
            lambda user, permission, content: user.username != 'hop-cy',
            ('holder__via_manager', 8),
        )
        for name, selected in (
            ('ada', True), ('ben', True), ('cy', False),
            ('dee', True), ('eve', True),
        ):
            with self.subTest(user=name, walk='leaf'):
                self._expect(
                    leaf, self.people[name], selected=selected, plain=True,
                )

        parent = self.Crew.objects.create(name='parent', auth_group=self.group)
        child = self.Crew.objects.create(
            name='child', parent=parent, auth_group=self.group,
        )
        parent.members.add(self.people['ada'])
        child.members.add(self.people['ben'], self.people['cy'])
        self.CrewGrant.objects.create(
            crew=child, auth_group=self.group, task=self.task,
        )
        crew = compiler(path='tests.core.via-hop.crew')
        crew.add_named_filter(self.Task, 'kept', kept)
        crew.register(
            trust=self.CrewGrant,
            user='crew__members',
            group='auth_group',
            content='task',
            via=('crew__children', 8),
        )
        for name, selected in (('ben', False), ('cy', True), ('ada', True)):
            with self.subTest(user=name, walk='group'):
                self._expect(
                    crew, self.people[name], selected=selected, plain=True,
                )

    def test_filter_on_delegate_sponsor_and_reset(self):
        self._activate()
        User = self.User
        ada, ben, cy, dee, eve = (
            self.people[name] for name in ('ada', 'ben', 'cy', 'dee', 'eve')
        )
        zed = User.objects.create_user('hop-zed', password='x')

        class DeskGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            task = models.ForeignKey(self.Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_desk_grant'

        class Bridge(models.Model):
            task = models.ForeignKey(self.Task, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_hop_bridge'

        cm = _tables(DeskGrant, Bridge)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        kept = lambda user, permission, content: user.username != 'hop-ben'
        DeskGrant.objects.create(
            user=ada, permission=self.change, task=self.task,
        )
        Bridge.objects.create(task=self.task, delegate=ada, sponsor=ada)
        delegate = compiler(path='tests.core.via-hop.delegate')
        delegate.add_named_filter(self.Task, 'kept', kept)
        delegate.register(
            trust=DeskGrant,
            user='user',
            permission='permission',
            content='task',
        )
        delegate.register(
            trust=Bridge,
            delegate='delegate',
            sponsor='sponsor',
            content='task',
            via=('delegate__via_manager', 8),
        )
        for name, selected in (
            ('ada', True), ('dee', True), ('eve', True),
            ('ben', False), ('cy', False),
        ):
            with self.subTest(user=name, walk='delegate'):
                self._expect(
                    delegate, self.people[name],
                    selected=selected, plain=True, group=False,
                )
        self.assertIs(
            self._bundle(delegate, zed, filtered=True)['has'], False,
        )

        sponsor = compiler(path='tests.core.via-hop.sponsor')
        sponsor.add_named_filter(self.Task, 'kept', kept)
        sponsor.register(
            trust=DeskGrant,
            user='user',
            permission='permission',
            content='task',
        )
        sponsor.register(
            trust=Bridge,
            delegate='delegate',
            sponsor='sponsor',
            content='task',
            via=('sponsor__via_manager', 8),
        )
        Bridge.objects.all().delete()
        Bridge.objects.create(task=self.task, delegate=zed, sponsor=ada)
        DeskGrant.objects.filter(user=ada).update(user=dee)
        with self.subTest(walk='sponsor', grant='dee'):
            self.assertIs(self._bundle(sponsor, zed, filtered=True)['has'], True)
        DeskGrant.objects.filter(user=dee).update(user=cy)
        with self.subTest(walk='sponsor', grant='cy'):
            self.assertIs(self._bundle(sponsor, zed, filtered=True)['has'], False)

        dee.via_reset = True
        dee.save(update_fields=['via_reset'])
        reset = self._seat(
            'reset',
            lambda user, permission, content: user.username != 'hop-nobody',
            ('holder__via_manager', 8, 'via_reset'),
        )
        for name, selected in (
            ('ada', True), ('ben', True), ('cy', True),
            ('dee', False), ('eve', False),
        ):
            with self.subTest(user=name, walk='reset'):
                self._expect(
                    reset, self.people[name], selected=selected, plain=selected,
                )
        blocked = self._seat(
            'reset-seed',
            lambda user, permission, content: user.username != 'hop-ada',
            ('holder__via_manager', 8, 'via_reset'),
        )
        for name, plain in (
            ('ada', True), ('ben', True), ('cy', True),
            ('dee', False), ('eve', False),
        ):
            with self.subTest(user=name, walk='reset-seed'):
                self._expect(
                    blocked, self.people[name], selected=False, plain=plain,
                )

    def test_user_condition_stops_at_each_hop(self):
        self._activate()
        places = (
            ('grant', 'ada', {'ada': False, 'ben': False, 'cy': False, 'dee': False, 'eve': False}),
            ('middle', 'ben', {'ada': True, 'ben': False, 'cy': False, 'dee': True, 'eve': True}),
            ('last', 'cy', {'ada': True, 'ben': True, 'cy': False, 'dee': True, 'eve': True}),
        )
        for place, stopped, expected in places:
            with self.subTest(place=place):
                handle = compiler(path='tests.core.via-hop.cond-%s' % place)
                handle.set_user_condition(
                    'called',
                    lambda user, stopped=stopped: user.username != 'hop-%s' % stopped,
                )
                handle.register(
                    trust=self.Seat,
                    user='holder',
                    group='auth_group',
                    content='task',
                    via=('holder__via_manager', 8),
                )
                with _listed(handle):
                    seen = {
                        name: user.has_perm(self.code, self.task)
                        for name, user in self.people.items()
                    }
                for name, allowed in expected.items():
                    self.assertIs(seen[name], allowed, name)

    def test_null_comparison_on_either_side(self):
        self._activate()
        passing = {'ada': True, 'ben': False, 'cy': False, 'dee': True, 'eve': True}
        cases = (
            (
                'eq-none-right',
                lambda user: user.via_nick == None,  # noqa: E711
                {'ada': None, 'ben': 'ben', 'dee': None, 'eve': None},
                {},
                passing,
            ),
            (
                'eq-none-left',
                lambda user: None == user.via_nick,  # noqa: E711
                {'ada': None, 'ben': 'ben', 'dee': None, 'eve': None},
                {},
                passing,
            ),
            (
                'ne-none-right',
                lambda user: user.via_nick != None,  # noqa: E711
                {'ada': 'ada', 'ben': None, 'dee': 'dee', 'eve': 'eve'},
                {},
                passing,
            ),
            (
                'ne-none-left',
                lambda user: None != user.via_nick,  # noqa: E711
                {'ada': 'ada', 'ben': None, 'dee': 'dee', 'eve': 'eve'},
                {},
                passing,
            ),
            (
                'eq-bool-none',
                lambda user: user.via_reset == None,  # noqa: E711
                {},
                {'ada': None, 'ben': True, 'dee': None, 'eve': None},
                passing,
            ),
            (
                'ne-bool-none',
                lambda user: user.via_reset != None,  # noqa: E711
                {},
                {'ada': True, 'ben': None, 'dee': True, 'eve': True},
                passing,
            ),
            (
                'eq-null-field',
                lambda user: user.via_nick == 'keep',
                {'ada': 'keep', 'ben': None, 'dee': 'keep', 'eve': 'keep'},
                {},
                passing,
            ),
            (
                'ne-null-field',
                lambda user: user.via_nick != 'stop',
                {'ada': 'keep', 'ben': None, 'dee': 'keep', 'eve': 'stop'},
                {},
                # ben's NULL comparison is unknown and does not grant, so
                # the walk stops before cy. cy's own nick would match.
                {'ada': True, 'ben': False, 'cy': False, 'dee': True, 'eve': False},
            ),
            (
                'eq-two-fields',
                lambda user: user.via_nick == user.via_other,
                {'ada': 'ada', 'ben': None, 'dee': 'dee', 'eve': 'eve'},
                {},
                passing,
            ),
            (
                'ne-two-fields',
                lambda user: user.via_nick != user.via_other,
                {'ada': 'ada', 'ben': 'ben', 'dee': None, 'eve': 'eve'},
                {},
                {'ada': True, 'ben': False, 'cy': False, 'dee': False, 'eve': False},
            ),
        )
        for label, predicate, nicks, flags, expected in cases:
            with self.subTest(label):
                for name, value in nicks.items():
                    person = self.people[name]
                    person.via_nick = value
                    person.via_other = value if label != 'ne-two-fields' else (
                        'other' if name == 'ada' else value
                    )
                    if label == 'eq-two-fields' and name == 'ben':
                        person.via_other = 'ben'
                    person.save(update_fields=['via_nick', 'via_other'])
                self.people['cy'].via_nick = 'cy'
                self.people['cy'].via_other = 'cy'
                self.people['cy'].save(update_fields=['via_nick', 'via_other'])
                for name, value in flags.items():
                    person = self.people[name]
                    person.via_reset = value
                    person.save(update_fields=['via_reset'])
                handle = compiler(path='tests.core.via-hop.%s' % label)
                handle.set_user_condition('nick', predicate)
                handle.register(
                    trust=self.Seat,
                    user='holder',
                    group='auth_group',
                    content='task',
                    via=('holder__via_manager', 8),
                )
                with _listed(handle):
                    seen = {
                        name: user.has_perm(self.code, self.task)
                        for name, user in self.people.items()
                    }
                for name, allowed in expected.items():
                    self.assertIs(seen[name], allowed, name)
        with self.assertRaises(PermissionConditionError) as raised:
            compiler(path='tests.core.via-hop.ordered').set_user_condition(
                'nick', lambda user: user.via_nick < 'm',
            )
        self.assertIn('Ordered comparison', str(raised.exception))

    def test_hop_matches_permitted_on_null_bool_negation_and_compare(self):
        """The walked user and a direct ``.permitted()`` agree.

        Each case is the grant holder, so the hop seed and the queryset
        condition read the same row. One expected value is both answers.
        A NULL column compared with ``!=`` is unknown, so it does not
        grant, on the walked hop and on ``.permitted()``. ``!= None`` is
        the negation of ``== None``: unknown when the value is missing,
        true only for a reached non-NULL column.
        """
        self._activate()
        ada = self.people['ada']
        cases = (
            ('null-eq', lambda user: user.via_nick == None,  # noqa: E711
             dict(via_nick=None, via_other=None, via_reset=None), True),
            ('null-ne', lambda user: user.via_nick != None,  # noqa: E711
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('value-eq-null', lambda user: user.via_nick == None,  # noqa: E711
             dict(via_nick='ada', via_other='ada', via_reset=True), False),
            ('value-ne-null', lambda user: user.via_nick != None,  # noqa: E711
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('null-eq-const', lambda user: user.via_nick == 'ada',
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('null-ne-const', lambda user: user.via_nick != 'ada',
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('eq-const', lambda user: user.via_nick == 'ada',
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('ne-const', lambda user: user.via_nick != 'ada',
             dict(via_nick='ada', via_other='ada', via_reset=True), False),
            ('null-eq-col', lambda user: user.via_nick == user.via_other,
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('eq-col', lambda user: user.via_nick == user.via_other,
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('ne-col', lambda user: user.via_nick != user.via_other,
             dict(via_nick='ada', via_other='bee', via_reset=True), True),
            ('null-ne-col', lambda user: user.via_nick != user.via_other,
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('bool-true', lambda user: user.via_reset == True,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('bool-false', lambda user: user.via_reset == False,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=False), True),
            ('bool-null-eq', lambda user: user.via_reset == True,  # noqa: E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('bool-null-eq-false', lambda user: user.via_reset == False,  # noqa: E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('bool-ne-true', lambda user: user.via_reset != True,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=False), True),
            ('ne-bool-null', lambda user: user.via_reset != True,  # noqa: E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('ne-bool-null-false', lambda user: user.via_reset != False,  # noqa: E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('bool-ne-false', lambda user: user.via_reset != False,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('ne-bool-false-held', lambda user: user.via_reset != False,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=False), False),
            ('ne-bool-held', lambda user: user.via_reset != True,  # noqa: E712
             dict(via_nick='ada', via_other='ada', via_reset=True), False),
            ('guard-null-ne-true',
             lambda user: (user.via_reset != None) & (user.via_reset != True),  # noqa: E711, E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('guard-null-ne-false',
             lambda user: (user.via_reset != None) & (user.via_reset != False),  # noqa: E711, E712
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('guard-false-ne-true',
             lambda user: (user.via_reset != None) & (user.via_reset != True),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=False), True),
            ('guard-true-ne-false',
             lambda user: (user.via_reset != None) & (user.via_reset != False),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('guard-true-ne-true',
             lambda user: (user.via_reset != None) & (user.via_reset != True),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=True), False),
            ('guard-false-ne-false',
             lambda user: (user.via_reset != None) & (user.via_reset != False),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=False), False),
            ('not-bool', lambda user: ~user.via_reset,
             dict(via_nick='ada', via_other='ada', via_reset=True), False),
            ('not-bool-false', lambda user: ~user.via_reset,
             dict(via_nick='ada', via_other='ada', via_reset=False), True),
            ('not-bool-null', lambda user: ~user.via_reset,
             dict(via_nick=None, via_other=None, via_reset=None), False),
            ('or-null', lambda user: (user.via_nick == None) | (user.via_reset == True),  # noqa: E711, E712
             dict(via_nick=None, via_other=None, via_reset=None), True),
            ('or-miss', lambda user: (user.via_nick == None) | (user.via_reset == True),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=False), False),
            ('and-pass', lambda user: (user.via_nick != None) & (user.via_reset == True),  # noqa: E711, E712
             dict(via_nick='ada', via_other='ada', via_reset=True), True),
            ('and-null', lambda user: (user.via_nick != None) & (user.via_reset == True),  # noqa: E711, E712
             dict(via_nick=None, via_other=None, via_reset=True), False),
        )
        for label, predicate, values, expected in cases:
            with self.subTest(label):
                ada.via_nick = values['via_nick']
                ada.via_other = values['via_other']
                ada.via_reset = values['via_reset']
                ada.save(update_fields=['via_nick', 'via_other', 'via_reset'])
                direct = compiler(path='tests.core.via-pin.direct-%s' % label)
                direct.set_user_condition('pin', predicate)
                direct.register(
                    trust=self.Seat, user='holder', group='auth_group',
                    content='task',
                )
                walked = compiler(path='tests.core.via-pin.walk-%s' % label)
                walked.set_user_condition('pin', predicate)
                walked.register(
                    trust=self.Seat, user='holder', group='auth_group',
                    content='task', via=('holder__via_manager', 8),
                )
                direct_has, direct_permitted = self._holder_answer(direct, ada)
                walk_has, walk_permitted = self._holder_answer(walked, ada)
                self.assertEqual(
                    (direct_has, direct_permitted, walk_has, walk_permitted),
                    (expected, expected, expected, expected),
                )

    def test_contains_object_and_permission_on_the_hop(self):
        """Membership, the protected object, and the permission terminal."""
        self._activate()
        ada = self.people['ada']
        ben = self.people['ben']
        ada.groups.add(self.group)
        groups = compiler(path='tests.core.via-hop.groups')
        groups.set_user_condition(
            'member', lambda user: user.groups.contains(self.group),
        )
        groups.register(
            trust=self.Seat, user='holder', group='auth_group',
            content='task', via=('holder__via_manager', 8),
        )
        with _listed(groups):
            self.assertIs(ada.has_perm(self.code, self.task), True)
            self.assertIs(ben.has_perm(self.code, self.task), False)
        ada.via_nick = 'hop-ada'
        ada.save(update_fields=['via_nick'])
        ben.via_manager = ada
        ben.save(update_fields=['via_manager'])
        held = compiler(path='tests.core.via-hop.manager')
        held.set_user_condition(
            'managed',
            lambda user: user.via_manager.contains(ada) | (user.username == 'hop-ada'),
        )
        held.register(
            trust=self.Seat, user='holder', group='auth_group',
            content='task', via=('holder__via_manager', 8),
        )
        with _listed(held):
            self.assertIs(ada.has_perm(self.code, self.task), True)
            self.assertIs(ben.has_perm(self.code, self.task), True)
            self.assertIs(self.people['cy'].has_perm(self.code, self.task), False)
        ada.via_nick = self.task.name
        ada.save(update_fields=['via_nick'])
        named = self._seat(
            'object-nick',
            lambda user, permission, content: user.via_nick == content.name,
            ('holder__via_manager', 8),
        )
        self._expect(named, ada, selected=True, plain=True)
        self._expect(named, ben, selected=False, plain=True)
        ada.via_nick = 'change_hoptask'
        ada.save(update_fields=['via_nick'])
        coded = self._seat(
            'perm-code',
            lambda user, permission, content: user.via_nick == permission.codename,
            ('holder__via_manager', 8),
        )
        self._expect(coded, ada, selected=True, plain=True)
        self._expect(coded, ben, selected=False, plain=True)

    def _holder_answer(self, handle, user):
        with _listed(handle):
            has = user.has_perm(self.code, self.task)
            permitted = self.task.name in set(
                self.Task.objects.permitted(
                    self.code, user,
                ).values_list('name', flat=True)
            )
        return has, permitted


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaPermissionTerminalTest(TransactionTestCase):
    """The hop reads the permission terminal that register() stored."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        _add_user_column(
            self, Permission, 'via_code',
            models.CharField(
                max_length=40, unique=True, null=True, db_column='via_code_col',
            ),
        )
        _add_user_column(
            self, Permission, 'via_label',
            models.CharField(max_length=40, null=True, db_column='via_label_col'),
        )
        self.User = User
        self.ada = User.objects.create_user('term-ada', password='x')
        self.ben = User.objects.create_user('term-ben', password='x')
        self.ben.via_manager = self.ada
        self.ben.save()

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_task'

        class Renamed(models.Model):
            holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            permit = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='+')
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_renamed'

        class Collected(models.Model):
            holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            permits = models.ManyToManyField(Permission, related_name='+')
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_collected'

        class Targeted(models.Model):
            holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            permit = models.ForeignKey(
                Permission, to_field='via_code', db_column='permit_code',
                on_delete=models.CASCADE, related_name='+',
            )
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_targeted'

        class Stored(models.Model):
            holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            permit = models.ForeignKey(
                Permission, db_column='grant_permit',
                on_delete=models.CASCADE, related_name='+',
            )
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_stored'

        class Desk(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            permit = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='+')
            task = models.ForeignKey(Task, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_desk'

        class Bridge(models.Model):
            task = models.ForeignKey(Task, on_delete=models.CASCADE)
            delegate = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            sponsor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_term_bridge'

        _bind_m2m(Collected, 'permits', Permission)
        self.Task = Task
        self.models = (Task, Renamed, Collected, Targeted, Stored, Desk, Bridge)
        cm = _tables(*self.models)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Task, 'term-ada')
        self.change.via_code = 'term-code'
        self.change.via_label = 'term-ada'
        self.change.save(update_fields=['via_code', 'via_label'])
        self.code = 'trusts_tests.term-ada'
        self.task = Task.objects.create(name='task')
        self.rows = {
            'renamed': Renamed.objects.create(
                holder=self.ada, permit=self.change, task=self.task,
            ),
            'collected': Collected.objects.create(holder=self.ada, task=self.task),
            'to_field': Targeted.objects.create(
                holder=self.ada, permit=self.change, task=self.task,
            ),
            'db_column': Stored.objects.create(
                holder=self.ada, permit=self.change, task=self.task,
            ),
        }
        self.rows['collected'].permits.add(self.change)
        self.same = lambda user, permission, content: (
            user.username == permission.codename
        )

    def _open(self, name, model, permission):
        handle = compiler(path='tests.core.via-term.%s' % name)
        handle.add_named_filter(self.Task, 'kept', self.same)
        handle.register(
            trust=model,
            user='holder',
            permission=permission,
            content='task',
            via=('holder__via_manager', 8),
        )
        return handle

    def _sees(self, handle, user):
        code = 'trusts_tests.%s' % self.change.codename
        with _listed(handle):
            has = user.has_perm('%s:kept' % code, self.task)
            permitted = self.task.name in set(
                self.Task.objects.permitted(
                    code, user, conditions=('kept',),
                ).values_list('name', flat=True)
            )
        self.assertEqual(has, permitted)
        return has

    def test_each_terminal_shape(self):
        shapes = (
            ('renamed', self.models[1], 'permit'),
            ('collected', self.models[2], 'permits'),
            ('to_field', self.models[3], 'permit'),
            ('db_column', self.models[4], 'permit'),
        )
        for name, model, permission in shapes:
            with self.subTest(shape=name, label='grant'):
                handle = self._open(name, model, permission)
                self.change.codename = 'term-ada'
                self.change.save(update_fields=['codename'])
                self.assertIs(self._sees(handle, self.ada), True)
                self.assertIs(self._sees(handle, self.ben), False)
            with self.subTest(shape=name, label='middle'):
                self.change.codename = 'term-ben'
                self.change.save(update_fields=['codename'])
                self.assertIs(self._sees(handle, self.ada), False)
                self.assertIs(self._sees(handle, self.ben), False)

    def test_rejected_terminals(self):
        handle = compiler(path='tests.core.via-term.unequal')
        handle.add_named_filter(
            self.Task, 'kept',
            lambda user, permission, content: user.username != permission.codename,
        )
        with self.assertRaises(TrustsConfigurationError) as raised:
            handle.register(
                trust=self.models[2],
                user='holder',
                permission='permits',
                content='task',
                via=('holder__via_manager', 8),
            )
        self.assertIn('cannot be written', str(raised.exception))
        delegated = compiler(path='tests.core.via-term.delegated')
        delegated.add_named_filter(self.Task, 'kept', self.same)
        delegated.register(
            trust=self.models[5],
            user='user',
            permission='permit',
            content='task',
        )
        with self.assertRaises(TrustsConfigurationError) as raised:
            delegated.register(
                trust=self.models[6],
                delegate='delegate',
                sponsor='sponsor',
                content='task',
                via=('delegate__via_manager', 8),
            )
        self.assertIn('cannot be written', str(raised.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaForeignKeyTargetTest(TransactionTestCase):
    """Walk, reset, and membership joins use ``to_field`` and ``db_column``."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Team(models.Model):
            code = models.CharField(max_length=20, unique=True, db_column='team_code')
            parent = models.ForeignKey(
                'self', to_field='code', db_column='parent_code',
                null=True, related_name='children', on_delete=models.CASCADE,
            )
            captain = models.ForeignKey(
                User, to_field='username', db_column='captain_name',
                null=True, related_name='+', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True, db_column='cut_here')
            auth_group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_team'

        class Membership(models.Model):
            team = models.ForeignKey(
                Team, to_field='code', db_column='member_team',
                on_delete=models.CASCADE,
            )
            person = models.ForeignKey(
                User, to_field='username', db_column='person_name',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_member'

        Team.add_to_class(
            'members',
            models.ManyToManyField(User, through=Membership, related_name='+'),
        )

        class JobQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Job(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            team = models.ForeignKey(
                Team, to_field='code', db_column='job_team',
                related_name='jobs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(JobQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_job'

        class Grant(models.Model):
            team = models.ForeignKey(
                Team, to_field='code', db_column='grant_team',
                on_delete=models.CASCADE,
            )
            auth_group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_grant'

        class Link(models.Model):
            src = models.ForeignKey(
                Team, to_field='code', db_column='src_code',
                related_name='out_links', on_delete=models.CASCADE,
            )
            dst = models.ForeignKey(
                Team, to_field='code', db_column='dst_code',
                related_name='in_links', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_link'

        class Mark(models.Model):
            slug = models.CharField(max_length=20, unique=True, db_column='mark_slug')
            reset_inheritance = models.BooleanField(null=True, db_column='mark_cut')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_mark'

        class TeamMark(models.Model):
            team = models.ForeignKey(
                Team, to_field='code', db_column='mark_team',
                on_delete=models.CASCADE,
            )
            mark = models.ForeignKey(
                Mark, to_field='slug', db_column='mark_ref',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_team_mark'

        Team.add_to_class(
            'marks',
            models.ManyToManyField(Mark, through=TeamMark, related_name='+'),
        )
        _bind_m2m(Team, 'members', User)
        _bind_m2m(Team, 'marks', Mark)

        class Flag(models.Model):
            team = models.ForeignKey(
                Team, to_field='code', db_column='flag_team',
                related_name='flags', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True, db_column='flag_cut')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_flag'

        self.User, self.Team, self.Job = User, Team, Job
        self.Grant, self.Link, self.Mark, self.Flag = Grant, Link, Mark, Flag
        cm = _tables(Team, Membership, Job, Grant, Link, Mark, TeamMark, Flag)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Job, 'change_fkjob')
        self.code = 'trusts_tests.change_fkjob'
        self.people = {}
        for name in ('ada', 'ben', 'cy'):
            self.people[name] = User.objects.create_user(
                'fk-%s' % name, password='x',
            )
        root = self._team('root', None)
        mid = self._team('mid', root)
        leaf = self._team('leaf', mid)
        self.teams = {'root': root, 'mid': mid, 'leaf': leaf}
        for person, code in (('ada', 'root'), ('ben', 'mid'), ('cy', 'leaf')):
            team = self.teams[code]
            team.members.add(self.people[person])
            team.captain = self.people[person]
            team.save(update_fields=['captain'])
        Link.objects.create(src=root, dst=mid)
        Link.objects.create(src=mid, dst=leaf)
        self.jobs = {
            name: Job.objects.create(name=name, team=team)
            for name, team in self.teams.items()
        }

    def _team(self, code, parent):
        group = Group.objects.create(name='via-fk-%s' % code)
        group.permissions.add(self.change)
        return self.Team.objects.create(
            code=code, parent=parent, auth_group=group,
        )

    def _sees(self, handle, user, job):
        with _listed(handle):
            return user.has_perm(self.code, job)

    def _open(self, name, via, user='team__members'):
        handle = compiler(path='tests.core.via-fk.%s' % name)
        handle.register(
            trust=self.Grant,
            user=user,
            group='auth_group',
            content='team__jobs',
            via=via,
        )
        return handle

    def test_edge_and_membership_targets(self):
        grant = self.Grant.objects.create(
            team=self.teams['root'], auth_group=self.teams['root'].auth_group,
        )
        shapes = (
            ('down', ('team__parent', 8), 'root'),
            ('link', ('team__in_links__src', 8), 'root'),
        )
        for name, via, anchor in shapes:
            handle = self._open(name, via)
            job = self.jobs[anchor]
            with self.subTest(shape=name):
                for person in ('ada', 'ben', 'cy'):
                    self.assertIs(
                        self._sees(handle, self.people[person], job), True, person,
                    )
        grant.team = self.teams['leaf']
        grant.auth_group = self.teams['leaf'].auth_group
        grant.save(update_fields=['team', 'auth_group'])
        upward = self._open('up', ('team__children', 8))
        with self.subTest(shape='up'):
            for person in ('ada', 'ben', 'cy'):
                self.assertIs(
                    self._sees(upward, self.people[person], self.jobs['leaf']),
                    True, person,
                )

    def test_along_matches_the_grant_column(self):
        self.Grant.objects.create(
            team=self.teams['root'], auth_group=self.teams['root'].auth_group,
        )
        handle = compiler(path='tests.core.via-fk.along')
        handle.register(
            trust=self.Grant,
            user='team__members',
            group='auth_group',
            content='team__jobs',
            along=('team__parent', 8),
        )
        for name in ('root', 'mid', 'leaf'):
            self.assertIs(
                self._sees(handle, self.people['ada'], self.jobs[name]),
                True, name,
            )
        self.assertIs(
            self._sees(handle, self.people['ben'], self.jobs['leaf']), False,
        )
    def test_user_walk_identity_is_the_to_field(self):
        User = self.User
        _add_user_column(
            self, User, 'lead',
            models.ForeignKey(
                'self', to_field='username', db_column='lead_name',
                null=True, related_name='led', on_delete=models.DO_NOTHING,
                db_constraint=False, db_index=False,
            ),
        )
        ada, ben, cy = (self.people[name] for name in ('ada', 'ben', 'cy'))
        ben.lead = ada
        ben.save(update_fields=['lead'])
        cy.lead = ben
        cy.save(update_fields=['lead'])

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, to_field='username', db_column='holder_name',
                on_delete=models.CASCADE, related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            job = models.ForeignKey(self.Job, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_fk_seat'

        cm = _tables(Seat)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        Seat.objects.create(
            holder=ada, auth_group=self.teams['root'].auth_group,
            job=self.jobs['root'],
        )
        handle = compiler(path='tests.core.via-fk.user')
        handle.register(
            trust=Seat,
            user='holder',
            group='auth_group',
            content='job',
            via=('holder__lead', 8),
        )
        for name in ('ada', 'ben', 'cy'):
            self.assertIs(
                self._sees(handle, self.people[name], self.jobs['root']),
                True, name,
            )

    def test_reset_targets(self):
        self.Grant.objects.create(
            team=self.teams['root'], auth_group=self.teams['root'].auth_group,
        )
        mark = self.Mark.objects.create(slug='stop', reset_inheritance=True)
        self.teams['mid'].marks.add(mark)
        self.Flag.objects.create(team=self.teams['mid'], reset_inheritance=True)
        self.teams['mid'].reset_inheritance = True
        self.teams['mid'].save(update_fields=['reset_inheritance'])
        cases = (
            ('node', ('team__parent', 8, 'reset_inheritance')),
            ('m2m', ('team__parent', 8, 'marks__reset_inheritance')),
            ('reverse', ('team__parent', 8, 'flags__reset_inheritance')),
        )
        for name, via in cases:
            handle = self._open(name, via)
            job = self.jobs['root']
            with self.subTest(reset=name):
                self.assertIs(self._sees(handle, self.people['ada'], job), True)
                self.assertIs(self._sees(handle, self.people['ben'], job), False)
                self.assertIs(self._sees(handle, self.people['cy'], job), False)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaInquiryParityTest(TransactionTestCase):
    """The six inquiries agree on an ordinary group registration."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_parity_folder'

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='tasks', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_parity_task'

        class Seat(models.Model):
            holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            auth_group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='+')
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_parity_seat'

        self.User, self.Folder, self.Task, self.Seat = User, Folder, Task, Seat
        cm = _tables(Folder, Task, Seat)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Task, 'change_paritytask')
        self.code = 'trusts_tests.change_paritytask'
        self.folder = Folder.objects.create(name='folder')
        self.task = Task.objects.create(name='task', folder=self.folder)
        self.people = {}
        for name in ('ada', 'ben', 'cy', 'dee'):
            self.people[name] = User.objects.create_user(
                'parity-%s' % name, password='x',
            )
        ada, ben, cy, dee = (
            self.people[name] for name in ('ada', 'ben', 'cy', 'dee')
        )
        ben.via_manager = ada
        ben.is_active = False
        ben.save()
        cy.via_manager = ben
        cy.save()
        dee.via_manager = ada
        dee.save()
        group = Group.objects.create(name='via-parity')
        group.permissions.add(self.change)
        Seat.objects.create(holder=ada, auth_group=group, folder=self.folder)
        self.handle = compiler(path='tests.core.via-parity')
        self.handle.register(
            trust=Seat,
            user='holder',
            group='auth_group',
            content='folder__tasks',
            via=('holder__via_manager', 8),
        )

    def _answers(self, user):
        catalog = built_catalog(self.handle)
        task = self.task
        with _listed(self.handle):
            permitted = task.name in set(
                self.Task.objects.permitted(
                    self.code, user,
                ).values_list('name', flat=True)
            )
            has = user.has_perm(self.code, task)
            reached = task.get_permitted_users(self.change).filter(
                pk=user.pk,
            ).exists()

            @authorization_required(self.Task, self.code)
            def view(request, pk):
                return 'ok'

            try:
                view(_request(user), pk=task.pk)
                guarded = True
            except PermissionDenied:
                guarded = False
        common = catalog.permissions_for(user, task)
        if common == ():
            listed = False
        else:
            listed = self.change.pk in set(common.values_list('pk', flat=True))
        folders = self.folder.pk in set(
            scoped_permitted_content(
                self.Folder.objects.all(), user, self.change,
                content=self.Task, registry=catalog,
            ).values_list('pk', flat=True)
        )
        return {
            'permitted': permitted,
            'has_perm': has,
            'get_permitted_users': reached,
            'filter_by_permitted_content': folders,
            'common_permissions': listed,
            'authorization_required': guarded,
        }

    def test_six_inquiries_agree(self):
        expected = {'ada': True, 'ben': False, 'cy': False, 'dee': True}
        for name, allowed in expected.items():
            with self.subTest(user=name):
                answers = self._answers(self.people[name])
                self.assertEqual(set(answers.values()), {allowed}, answers)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaPermittedContentFilterTest(TransactionTestCase):
    """``conditions=`` matches ``permitted()`` on the same registration.

    The settled row is a grant on cabinet ``root`` with
    ``along=("cabinet__parent", 1)`` and sheets titled ``root``,
    ``child``, and ``past``. ``conditions=("titled",)`` where
    ``titled`` is ``content.title == "child"`` keeps the child sheet.
    ``filter_by_permitted_content`` then keeps the child cabinet, which
    is that sheet's prefix, and not ``root``.

    An office stored on the grant stays listed when the matching sheet
    hangs off a cabinet in another office. ``get_all_permissions``
    still returns the codename: that inquiry does not take
    ``conditions``.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Cabinet(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_cabinet'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_grant'

        self.User, self.Cabinet, self.Sheet, self.Grant = (
            User, Cabinet, Sheet, Grant,
        )
        cm = _tables(Cabinet, Sheet, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Sheet, 'change_filtersheet')
        self.code = 'trusts_tests.change_filtersheet'
        self.alice = User.objects.create_user('filter-alice', password='x')
        self.root = Cabinet.objects.create(title='root')
        self.child = Cabinet.objects.create(title='child', parent=self.root)
        self.past = Cabinet.objects.create(title='past', parent=self.child)
        self.sheets = {}
        for cabinet in (self.root, self.child, self.past):
            self.sheets[cabinet.pk] = Sheet.objects.create(
                title=cabinet.title, cabinet=cabinet,
            )
        group = Group.objects.create(name='via-filter')
        group.permissions.add(self.change)
        Grant.objects.create(
            user=self.alice, cabinet=self.root, auth_group=group,
        )
        self.handle = compiler(path='tests.core.via-content-filter')
        self.handle.add_named_filter(
            Sheet, 'titled',
            lambda user, permission, content: content.title == 'child',
        )
        self.handle.register(
            trust=Grant,
            user='user',
            group='auth_group',
            content='cabinet__sheets',
            along=('cabinet__parent', 1),
        )

    def _listed(self, user, conditions=()):
        with _listed(self.handle):
            sheets = set(self.Sheet.objects.permitted(
                self.code, user, conditions=conditions,
            ).values_list('pk', flat=True))
            cabinets = set(filter_by_permitted_content(
                self.Cabinet.objects.all(), user, self.change,
                content=self.Sheet, conditions=conditions,
            ).values_list('pk', flat=True))
            codes = user.get_all_permissions(self.sheets[self.child.pk])
        return sheets, cabinets, codes

    def test_content_filter_matches_permitted_sheets(self):
        plain_sheets, plain_cabinets, _codes = self._listed(self.alice)
        self.assertEqual(plain_sheets, {
            self.sheets[self.root.pk].pk,
            self.sheets[self.child.pk].pk,
        })
        self.assertEqual(plain_cabinets, {self.root.pk, self.child.pk})
        sheets, cabinets, codes = self._listed(self.alice, ('titled',))
        self.assertEqual(sheets, {self.sheets[self.child.pk].pk})
        self.assertEqual(cabinets, {self.child.pk})
        self.assertIn(self.code, codes)
        self.assertNotIn(self.past.pk, cabinets)

    def test_missing_and_malformed_conditions_return_nothing(self):
        with _listed(self.handle):
            with self.assertNumQueries(0):
                missing = list(filter_by_permitted_content(
                    self.Cabinet.objects.all(), self.alice, self.change,
                    content=self.Sheet, conditions=('missing',),
                ))
                malformed = list(filter_by_permitted_content(
                    self.Cabinet.objects.all(), self.alice, self.change,
                    content=self.Sheet, conditions=['titled'],
                ))
        self.assertEqual(missing, [])
        self.assertEqual(malformed, [])

    def test_user_filter_on_a_via_walk_matches_permitted(self):
        User = self.User
        _attach_manager(self, User)
        ada = User.objects.create_user('pcf-ada', password='x')
        ben = User.objects.create_user('pcf-ben', password='x')
        cy = User.objects.create_user('pcf-cy', password='x')
        ben.via_manager = ada
        ben.save()
        cy.via_manager = ben
        cy.save()

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_folder'

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(models.Model):
            name = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='tasks', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_task'

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_seat'

        with _tables(Folder, Task, Seat):
            change = _permission(Task, 'change_filtertask')
            code = 'trusts_tests.change_filtertask'
            folder = Folder.objects.create(name='folder')
            Task.objects.create(name='task', folder=folder)
            group = Group.objects.create(name='via-user-filter')
            group.permissions.add(change)
            Seat.objects.create(
                holder=ada, auth_group=group, folder=folder,
            )
            handle = compiler(path='tests.core.via-user-filter')
            handle.add_named_filter(
                Task, 'kept',
                lambda user, permission, content: user.username != 'pcf-ben',
            )
            handle.register(
                trust=Seat,
                user='holder',
                group='auth_group',
                content='folder__tasks',
                via=('holder__via_manager', 8),
            )
            expected = {ada: True, ben: False, cy: False}
            with _listed(handle):
                plain = set(Task.objects.permitted(
                    code, ben,
                ).values_list('pk', flat=True))
                self.assertTrue(plain)
                for user, allowed in expected.items():
                    with self.subTest(user=user.username):
                        permitted = set(Task.objects.permitted(
                            code, user, conditions=('kept',),
                        ).values_list('folder_id', flat=True))
                        folders = set(filter_by_permitted_content(
                            Folder.objects.all(), user, change,
                            content=Task, conditions=('kept',),
                        ).values_list('pk', flat=True))
                        if allowed:
                            self.assertEqual(permitted, {folder.pk})
                            self.assertEqual(folders, {folder.pk})
                        else:
                            self.assertEqual(permitted, set())
                            self.assertEqual(folders, set())

    def test_content_filter_correlates_on_to_field(self):
        User = self.User

        class Node(models.Model):
            code = models.CharField(max_length=20, unique=True)
            parent = models.ForeignKey(
                'self', to_field='code', db_column='parent_code',
                null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_tf_node'

        class DocQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Doc(models.Model):
            title = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, to_field='code', db_column='node_code',
                related_name='docs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(DocQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_tf_doc'

        class NodeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(
                Node, to_field='code', db_column='grant_node',
                on_delete=models.CASCADE,
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_tf_grant'

        with _tables(Node, Doc, NodeGrant):
            change = _permission(Doc, 'change_filterdoc')
            code = 'trusts_tests.change_filterdoc'
            root = Node.objects.create(code='root')
            child = Node.objects.create(code='child', parent=root)
            Doc.objects.create(title='root', node=root)
            child_doc = Doc.objects.create(title='child', node=child)
            group = Group.objects.create(name='via-filter-tf')
            group.permissions.add(change)
            NodeGrant.objects.create(
                user=self.alice, node=root, auth_group=group,
            )
            handle = compiler(path='tests.core.via-content-to-field')
            handle.add_named_filter(
                Doc, 'titled',
                lambda user, permission, content: content.title == 'child',
            )
            handle.register(
                trust=NodeGrant,
                user='user',
                group='auth_group',
                content='node__docs',
                along=('node__parent', 1),
            )
            with _listed(handle):
                docs = set(Doc.objects.permitted(
                    code, self.alice, conditions=('titled',),
                ).values_list('pk', flat=True))
                nodes = set(filter_by_permitted_content(
                    Node.objects.all(), self.alice, change,
                    content=Doc, conditions=('titled',),
                ).values_list('pk', flat=True))
            self.assertEqual(docs, {child_doc.pk})
            self.assertEqual(nodes, {child.pk})

    def test_ancestor_prefix_follows_the_grant_not_the_sheet_office(self):
        User = self.User

        class Office(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_office'

        class AncCabinet(models.Model):
            title = models.CharField(max_length=20)
            office = models.ForeignKey(
                Office, related_name='cabinets', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_anc_cabinet'

        class AncQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class AncSheet(models.Model):
            title = models.CharField(max_length=20)
            cabinet = models.ForeignKey(
                AncCabinet, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(AncQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_anc_sheet'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_office_grant'

        with _tables(Office, AncCabinet, AncSheet, OfficeGrant):
            change = _permission(AncSheet, 'change_ancsheet')
            code = 'trusts_tests.change_ancsheet'
            # A grant created first keeps the real grant's pk off the
            # office pk, so the walk seed cannot pass by matching those.
            decoy_user = User.objects.create_user(
                'filter-anc-decoy', password='x',
            )
            decoy_office = Office.objects.create(title='decoy')
            office = Office.objects.create(title='office')
            other = Office.objects.create(title='other')
            OfficeGrant.objects.create(
                user=decoy_user, office=decoy_office, permission=change,
            )
            root = AncCabinet.objects.create(title='root', office=office)
            child = AncCabinet.objects.create(
                title='child', office=other, parent=root,
            )
            AncSheet.objects.create(title='root', cabinet=root)
            child_sheet = AncSheet.objects.create(title='child', cabinet=child)
            OfficeGrant.objects.create(
                user=self.alice, office=office, permission=change,
            )
            handle = compiler(path='tests.core.via-ancestor-filter')
            handle.add_named_filter(
                AncSheet, 'titled',
                lambda user, permission, content: content.title == 'child',
            )
            handle.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__cabinets__sheets',
                along=('office__cabinets__parent', 1),
            )
            with _listed(handle):
                sheets = set(AncSheet.objects.permitted(
                    code, self.alice, conditions=('titled',),
                ).values_list('pk', flat=True))
                offices = set(filter_by_permitted_content(
                    Office.objects.all(), self.alice, change,
                    content=AncSheet, conditions=('titled',),
                ).values_list('pk', flat=True))
                cabinets = set(filter_by_permitted_content(
                    AncCabinet.objects.all(), self.alice, change,
                    content=AncSheet, conditions=('titled',),
                ).values_list('pk', flat=True))
            self.assertEqual(sheets, {child_sheet.pk})
            self.assertEqual(offices, {office.pk})
            self.assertNotIn(other.pk, offices)
            self.assertEqual(cabinets, {child.pk})

            class Handoff(models.Model):
                office = models.ForeignKey(Office, on_delete=models.CASCADE)
                delegate = models.ForeignKey(
                    User, related_name='+', on_delete=models.CASCADE,
                )
                sponsor = models.ForeignKey(
                    User, related_name='+', on_delete=models.CASCADE,
                )

                class Meta:
                    app_label = 'trusts_tests'
                    db_table = 'via_filter_anc_handoff'

            with _tables(Handoff):
                delegate = User.objects.create_user(
                    'filter-anc-delegate', password='x',
                )
                Handoff.objects.create(
                    office=office, delegate=delegate, sponsor=self.alice,
                )
                delegated = compiler(path='tests.core.via-ancestor-delegated')
                delegated.add_named_filter(
                    AncSheet, 'titled',
                    lambda user, permission, content: content.title == 'child',
                )
                delegated.register(
                    trust=OfficeGrant,
                    user='user',
                    permission='permission',
                    content='office__cabinets__sheets',
                    along=('office__cabinets__parent', 1),
                )
                delegated.register(
                    trust=Handoff,
                    delegate='delegate',
                    sponsor='sponsor',
                    content='office__cabinets__sheets',
                    along=('office__cabinets__parent', 1),
                )
                with _listed(delegated):
                    delegated_sheets = set(AncSheet.objects.permitted(
                        code, delegate, conditions=('titled',),
                    ).values_list('pk', flat=True))
                    delegated_offices = set(filter_by_permitted_content(
                        Office.objects.all(), delegate, change,
                        content=AncSheet, conditions=('titled',),
                    ).values_list('pk', flat=True))
                self.assertEqual(delegated_sheets, {child_sheet.pk})
                self.assertEqual(delegated_offices, {office.pk})
                self.assertNotIn(other.pk, delegated_offices)

    def test_delegated_ancestor_requires_one_sheet_in_both_walks(self):
        """One sheet has to pass the filter and both along walks.

        Office A holds ``root``. ``above`` is ``root``'s parent and lives
        in another office. ``child`` is ``root``'s child and lives in a
        third. The sponsor walks up (``children``) and the delegate walks
        down (``parent``). ``root`` is in both walks. ``above`` is only
        in the sponsor walk. ``child`` is only in the delegate walk.
        """
        User = self.User

        class Office(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_both_office'

        class Node(models.Model):
            title = models.CharField(max_length=20)
            office = models.ForeignKey(
                Office, related_name='nodes', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_both_node'

        class DocQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Doc(models.Model):
            title = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, related_name='docs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(DocQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_both_doc'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_both_grant'

        class Handoff(models.Model):
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_both_handoff'

        with _tables(Office, Node, Doc, OfficeGrant, Handoff):
            change = _permission(Doc, 'change_bothdoc')
            code = 'trusts_tests.change_bothdoc'
            office = Office.objects.create(title='office')
            other = Office.objects.create(title='other')
            above_office = Office.objects.create(title='above')
            above = Node.objects.create(title='above', office=above_office)
            root = Node.objects.create(
                title='root', office=office, parent=above,
            )
            child = Node.objects.create(
                title='child', office=other, parent=root,
            )
            docs = {
                'both': Doc.objects.create(title='both', node=root),
                'up': Doc.objects.create(title='up', node=above),
                'down': Doc.objects.create(title='down', node=child),
            }
            OfficeGrant.objects.create(
                user=self.alice, office=office, permission=change,
            )
            delegate = User.objects.create_user(
                'filter-both-delegate', password='x',
            )
            Handoff.objects.create(
                office=office, delegate=delegate, sponsor=self.alice,
            )
            handle = compiler(path='tests.core.via-both-walks')
            for name in ('both', 'up', 'down', 'split'):
                handle.add_named_filter(
                    Doc, name,
                    lambda user, permission, content, name=name: (
                        content.title != 'both' if name == 'split'
                        else content.title == name
                    ),
                )
            handle.register(
                trust=OfficeGrant,
                user='user',
                permission='permission',
                content='office__nodes__docs',
                along=('office__nodes__children', 1),
            )
            handle.register(
                trust=Handoff,
                delegate='delegate',
                sponsor='sponsor',
                content='office__nodes__docs',
                along=('office__nodes__parent', 1),
            )
            expected = {
                'both': {docs['both'].pk},
                'up': set(),
                'down': set(),
                'split': set(),
            }
            with _listed(handle):
                for name, sheets in expected.items():
                    with self.subTest(sheet=name):
                        permitted = set(Doc.objects.permitted(
                            code, delegate, conditions=(name,),
                        ).values_list('pk', flat=True))
                        offices = set(filter_by_permitted_content(
                            Office.objects.all(), delegate, change,
                            content=Doc, conditions=(name,),
                        ).values_list('pk', flat=True))
                        self.assertEqual(permitted, sheets)
                        if sheets:
                            self.assertEqual(offices, {office.pk})
                        else:
                            self.assertEqual(offices, set())

    def test_delegated_walk_site_matches_permitted(self):
        User = self.User

        class Box(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_box'

        class PageQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Page(models.Model):
            title = models.CharField(max_length=20)
            box = models.ForeignKey(
                Box, related_name='pages', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(PageQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_page'

        class PageGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            box = models.ForeignKey(Box, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_page_grant'

        class Handoff(models.Model):
            box = models.ForeignKey(Box, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_filter_handoff'

        with _tables(Box, Page, PageGrant, Handoff):
            change = _permission(Page, 'change_filterpage')
            code = 'trusts_tests.change_filterpage'
            sponsor = User.objects.create_user('filter-sponsor', password='x')
            delegate = User.objects.create_user('filter-delegate', password='x')
            root = Box.objects.create(title='root')
            child = Box.objects.create(title='child', parent=root)
            Page.objects.create(title='root', box=root)
            child_page = Page.objects.create(title='child', box=child)
            PageGrant.objects.create(
                user=sponsor, box=root, permission=change,
            )
            Handoff.objects.create(
                box=root, delegate=delegate, sponsor=sponsor,
            )
            handle = compiler(path='tests.core.via-delegate-filter')
            handle.add_named_filter(
                Page, 'titled',
                lambda user, permission, content: content.title == 'child',
            )
            handle.register(
                trust=PageGrant,
                user='user',
                permission='permission',
                content='box__pages',
                along=('box__parent', 1),
            )
            handle.register(
                trust=Handoff,
                delegate='delegate',
                sponsor='sponsor',
                content='box__pages',
                along=('box__parent', 1),
            )
            with _listed(handle):
                pages = set(Page.objects.permitted(
                    code, delegate, conditions=('titled',),
                ).values_list('pk', flat=True))
                boxes = set(filter_by_permitted_content(
                    Box.objects.all(), delegate, change,
                    content=Page, conditions=('titled',),
                ).values_list('pk', flat=True))
            self.assertEqual(pages, {child_page.pk})
            self.assertEqual(boxes, {child.pk})


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class SavedObjectPathTest(TransactionTestCase):
    """A saved path walks relations and reads the target at the last step.

    ``desk.unit`` stores ``unit.code`` (``to_field``) in column
    ``unit_code`` (``db_column``). The related primary key is a different
    value. Instance checks, ``.permitted()``, ``get_permitted_users()``,
    and ``filter_by_permitted_content`` agree, including a null hop, a
    one-to-one, and a third hop. Delegate, sponsor, ``along=``, and
    ``via=`` use that same value.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        self.User = User

        class Unit(models.Model):
            code = models.CharField(max_length=20, unique=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_unit'

        class Desk(models.Model):
            unit = models.ForeignKey(
                Unit, to_field='code', db_column='unit_code',
                null=True, on_delete=models.CASCADE, related_name='desks',
            )
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            twin = models.OneToOneField(
                'self', null=True, related_name='card',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_desk'

        class Badge(models.Model):
            mark = models.ForeignKey(
                Unit, to_field='code', db_column='mark_code',
                null=True, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_badge'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            desk = models.ForeignKey(
                Desk, null=True, related_name='sheets',
                on_delete=models.CASCADE,
            )
            card = models.OneToOneField(
                Desk, null=True, related_name='card_sheet',
                on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_grant'

        class Handoff(models.Model):
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_path_handoff'

        self.Desk, self.Sheet = Desk, Sheet
        self.Grant, self.Handoff = Grant, Handoff
        cm = _tables(Unit, Desk, Badge, Sheet, Grant, Handoff)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        _add_user_column(
            self, User, 'unit',
            models.ForeignKey(
                Unit, to_field='code', db_column='unit_code',
                null=True, on_delete=models.DO_NOTHING,
                related_name='+', db_constraint=False, db_index=False,
            ),
        )
        _add_user_column(
            self, User, 'badge',
            models.ForeignKey(
                Badge, null=True, on_delete=models.DO_NOTHING,
                related_name='+', db_constraint=False, db_index=False,
            ),
        )
        eng = Unit.objects.create(code='ENG')
        Unit.objects.create(code='OTHER')
        self.assertNotEqual(eng.pk, eng.code)
        parent = Desk.objects.create(unit=None)
        home = Desk.objects.create(unit=eng, parent=parent)
        card = Desk.objects.create(unit=eng)
        home.twin = card
        home.save(update_fields=['twin'])
        bare = Desk.objects.create(unit=None)
        self.parent, self.home, self.bare = parent, home, bare
        self.matched = Sheet.objects.create(desk=home, card=card)
        self.empty = Sheet.objects.create(desk=bare, card=None)
        self.change = _permission(Sheet, 'change_pathsheet')
        self.code = 'trusts_tests.change_pathsheet'
        self.alice = User.objects.create_user('path-alice', password='x')
        self.bob = User.objects.create_user('path-bob', password='x')
        self.dan = User.objects.create_user('path-dan', password='x')
        self.alice.unit = eng
        self.alice.via_manager = self.bob
        self.alice.badge = Badge.objects.create(mark=eng)
        self.alice.save()
        self.bob.unit = Unit.objects.get(code='OTHER')
        self.bob.badge = Badge.objects.create(mark=self.bob.unit)
        self.bob.save()
        self.dan.unit = self.bob.unit
        self.dan.save()
        self.grant = Grant.objects.create(
            user=self.alice, desk=home, permission=self.change,
        )
        self.handoff = Handoff.objects.create(
            desk=home, delegate=self.dan, sponsor=self.alice,
        )

    def _register(self, name, predicate, *, via=None, along=None, delegate=False):
        handle = compiler(path='tests.core.via-path-%s' % name)
        handle.add_named_filter(self.Sheet, 'marked', predicate)
        grant = dict(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='desk__sheets',
        )
        hand = dict(
            trust=self.Handoff,
            delegate='delegate',
            sponsor='sponsor',
            content='desk__sheets',
        )
        if along is not None:
            grant['along'] = along
            hand['along'] = along
        if not delegate:
            if via is not None:
                grant['via'] = via
            handle.register(**grant)
        else:
            handle.register(**grant)
            if via is not None:
                hand['via'] = via
            handle.register(**hand)
        return handle

    def _surfaces(self, handle, sheet, user):
        code = '%s:marked' % self.code
        with _listed(handle):
            has = user.has_perm(code, sheet)
            permitted = set(self.Sheet.objects.permitted(
                self.code, user, conditions=('marked',),
            ).values_list('pk', flat=True))
            reached = set(sheet.get_permitted_users(code).values_list(
                'pk', flat=True,
            ))
            desks = set(filter_by_permitted_content(
                self.Desk.objects.all(), user, self.change,
                content=self.Sheet, conditions=('marked',),
            ).values_list('pk', flat=True))
        return has, permitted, reached, desks

    def test_saved_path_agrees_across_inquiries(self):
        desk_unit = (
            lambda user, permission, content: user.unit == content.desk.unit
        )
        card_unit = (
            lambda user, permission, content: user.unit == content.card.unit
        )
        deep_unit = (
            lambda user, permission, content: user.unit == content.desk.twin.unit
        )
        badge_mark = (
            lambda user, permission, content: user.badge.mark == content.desk.unit
        )
        cases = (
            ('via', desk_unit, dict(via=('user__via_manager', 1)), self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('via-other', desk_unit, dict(via=('user__via_manager', 1)), self.matched, self.bob, False, {self.alice.pk}, set()),
            ('null-unit', desk_unit, dict(via=('user__via_manager', 1)), self.empty, self.alice, False, set(), {self.home.pk}),
            ('one-to-one', card_unit, dict(via=('user__via_manager', 1)), self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('null-card', card_unit, dict(via=('user__via_manager', 1)), self.empty, self.alice, False, set(), {self.home.pk}),
            ('three-hop', deep_unit, dict(via=('user__via_manager', 1)), self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('null-twin', deep_unit, dict(via=('user__via_manager', 1)), self.empty, self.alice, False, set(), {self.home.pk}),
            ('badge', badge_mark, {}, self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('via-badge', badge_mark, dict(via=('user__via_manager', 1)), self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('badge-other', badge_mark, {}, self.matched, self.bob, False, {self.alice.pk}, set()),
            ('along', desk_unit, dict(via=('user__via_manager', 1), along=('desk__parent', 1)), self.matched, self.alice, True, {self.alice.pk}, {self.home.pk}),
            ('delegate', desk_unit, dict(via=('delegate__via_manager', 1), delegate=True), self.matched, self.dan, True, {self.alice.pk, self.dan.pk}, {self.home.pk}),
            ('sponsor', desk_unit, dict(via=('sponsor__via_manager', 1), delegate=True), self.matched, self.dan, False, {self.alice.pk}, set()),
        )
        for name, predicate, options, sheet, user, allowed, users, desks in cases:
            with self.subTest(name):
                self.dan.unit = (
                    self.alice.unit if name == 'delegate' else self.bob.unit
                )
                self.dan.save(update_fields=['unit'])
                anchor = self.parent if name == 'along' else self.home
                self.grant.desk = anchor
                self.grant.save(update_fields=['desk'])
                self.handoff.desk = anchor
                self.handoff.save(update_fields=['desk'])
                handle = self._register(name, predicate, **options)
                has, permitted, reached, listed = self._surfaces(
                    handle, sheet, user,
                )
                self.assertIs(has, allowed)
                self.assertEqual(sheet.pk in permitted, allowed)
                self.assertEqual(reached, users)
                self.assertEqual(listed, desks)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class CandidateContentIdentityTest(TransactionTestCase):
    """A longer via content path reads the candidate content row.

    Grant and content primary keys do not match, and a decoy content
    row uses the first grant's primary key. Two grants reach one sheet.
    Forward and inverse inquiries agree. ``get_all_permissions`` follows
    the unfiltered grant. ``get_group_permissions`` does not apply: the
    registration has no group terminal.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        self.User = User

        class Dept(models.Model):
            region = models.CharField(max_length=20)
            rank = models.IntegerField()
            flag = models.BooleanField()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_dept'

        class Unit(models.Model):
            code = models.CharField(max_length=20, unique=True)
            region = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_unit'

        class Cabinet(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_cabinet'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )
            dept = models.ForeignKey(Dept, on_delete=models.CASCADE)
            unit = models.ForeignKey(
                Unit, to_field='code', db_column='unit_code',
                on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_sheet'

        class Plaque(models.Model):
            sheet = models.OneToOneField(
                Sheet, related_name='plaque', on_delete=models.CASCADE,
            )
            label = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_plaque'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_id_grant'

        self.Sheet, self.Cabinet, self.Grant = Sheet, Cabinet, Grant
        cm = _tables(Dept, Unit, Cabinet, Sheet, Plaque, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        _add_user_column(
            self, User, 'home',
            models.ForeignKey(
                Dept, null=True, on_delete=models.DO_NOTHING,
                related_name='+', db_constraint=False, db_index=False,
            ),
        )
        _add_user_column(
            self, User, 'unit',
            models.ForeignKey(
                Unit, to_field='code', db_column='unit_code', null=True,
                on_delete=models.DO_NOTHING, related_name='+',
                db_constraint=False, db_index=False,
            ),
        )
        _add_user_column(
            self, User, 'nick',
            models.CharField(max_length=20, null=True),
        )
        _add_user_column(
            self, User, 'rank',
            models.IntegerField(null=True),
        )
        _add_user_column(
            self, User, 'flag',
            models.BooleanField(null=True),
        )
        east = Dept.objects.create(region='east', rank=7, flag=True)
        west = Dept.objects.create(region='west', rank=1, flag=False)
        east_unit = Unit.objects.create(code='E', region='east')
        west_unit = Unit.objects.create(code='W', region='west')
        self.assertNotEqual(east_unit.pk, east_unit.code)
        decoy_box = Cabinet.objects.create(pk=1, name='decoy')
        self.kept_box = Cabinet.objects.create(pk=7, name='kept')
        decoy = Sheet.objects.create(
            pk=1, title='decoy', cabinet=decoy_box, dept=west, unit=west_unit,
        )
        self.sheet = Sheet.objects.create(
            pk=40, title='kept', cabinet=self.kept_box, dept=east,
            unit=east_unit,
        )
        Plaque.objects.create(sheet=decoy, label='decoy')
        Plaque.objects.create(sheet=self.sheet, label='kept')
        self.change = _permission(Sheet, 'change_idsheet')
        self.code = 'trusts_tests.change_idsheet'
        self.ada = User.objects.create_user('id-ada', password='x')
        self.bea = User.objects.create_user('id-bea', password='x')
        self.cy = User.objects.create_user('id-cy', password='x')
        for user, dept, unit, nick, rank, flag in (
            (self.ada, east, east_unit, 'kept', 7, True),
            (self.bea, east, east_unit, 'kept', 7, True),
            (self.cy, west, west_unit, 'no', 1, False),
        ):
            user.home = dept
            user.unit = unit
            user.nick = nick
            user.rank = rank
            user.flag = flag
            user.save()
        self.ada_grant = Grant.objects.create(
            pk=1, user=self.ada, cabinet=self.kept_box, permission=self.change,
        )
        self.bea_grant = Grant.objects.create(
            pk=2, user=self.bea, cabinet=self.kept_box, permission=self.change,
        )
        Grant.objects.create(
            pk=3, user=self.cy, cabinet=self.kept_box, permission=self.change,
        )
        self.assertEqual(self.ada_grant.pk, decoy.pk)
        self.assertNotEqual(self.sheet.pk, self.ada_grant.pk)
        self.assertNotEqual(self.sheet.pk, self.bea_grant.pk)
        self.assertNotEqual(self.sheet.pk, self.kept_box.pk)

    def _register(self, name, predicate):
        handle = compiler(path='tests.core.via-id-%s' % name)
        handle.add_named_filter(self.Sheet, 'kept', predicate)
        handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='cabinet__sheets',
            via=('user__via_manager', 4),
        )
        return handle

    def _answers(self, handle, user):
        code = '%s:kept' % self.code
        sheet = self.sheet
        with _listed(handle):
            has = user.has_perm(code, sheet)
            permitted = sheet.pk in set(
                self.Sheet.objects.permitted(
                    self.code, user, conditions=('kept',),
                ).values_list('pk', flat=True)
            )
            reached = set(sheet.get_permitted_users(code).values_list(
                'pk', flat=True,
            ))
            listed = self.kept_box.pk in set(
                filter_by_permitted_content(
                    self.Cabinet.objects.all(), user, self.change,
                    content=self.Sheet, conditions=('kept',),
                ).values_list('pk', flat=True)
            )

            @authorization_required(self.Sheet, self.code, ('kept',))
            def view(request, pk):
                return 'ok'

            try:
                view(_request(user), pk=sheet.pk)
                guarded = True
            except PermissionDenied:
                guarded = False
            complete = self.code in user.get_all_permissions(sheet)
            grouped = self.code in user.get_group_permissions(sheet)
        return {
            'has_perm': has,
            'permitted': permitted,
            'get_permitted_users': user.pk in reached,
            'filter_by_permitted_content': listed,
            'authorization_required': guarded,
            'reached': reached,
            'get_all_permissions': complete,
            'get_group_permissions': grouped,
        }

    def test_candidate_content_id_agrees_across_inquiries(self):
        cases = (
            ('char', lambda user, permission, content: (
                user.home.region == content.dept.region
            )),
            ('bool', lambda user, permission, content: (
                user.flag == content.dept.flag
            )),
            ('int', lambda user, permission, content: (
                user.rank == content.dept.rank
            )),
            ('to-field', lambda user, permission, content: (
                user.unit.region == content.unit.region
            )),
            ('reverse-o2o', lambda user, permission, content: (
                user.nick == content.plaque.label
            )),
            ('length-1', lambda user, permission, content: (
                user.nick == content.title
            )),
        )
        for name, predicate in cases:
            handle = self._register(name, predicate)
            for user, expected in (
                (self.ada, True), (self.bea, True), (self.cy, False),
            ):
                with self.subTest(name=name, user=user.username):
                    answers = self._answers(handle, user)
                    filtered = {
                        key: answers[key]
                        for key in (
                            'has_perm',
                            'permitted',
                            'get_permitted_users',
                            'filter_by_permitted_content',
                            'authorization_required',
                        )
                    }
                    self.assertEqual(set(filtered.values()), {expected}, answers)
                    self.assertEqual(
                        answers['reached'], {self.ada.pk, self.bea.pk},
                    )
                    self.assertIs(answers['get_all_permissions'], True)
                    self.assertIs(answers['get_group_permissions'], False)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class SameCandidateRowTest(TransactionTestCase):
    """One protected row has to satisfy the hop and the overlay together.

    A prefix with two rows must be listed when only the later row
    qualifies. A hop value from one row must not combine with an
    overlay from the other. ``get_all_permissions`` and
    ``get_group_permissions`` do not take the named filter, so they
    are recorded separately and are not the expected value of the
    filtered inquiries.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        self.User = User

        class Desk(models.Model):
            closed = models.BooleanField(default=False)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_desk'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            region = models.CharField(max_length=20)
            mark = models.CharField(max_length=20)
            desk = models.ForeignKey(
                Desk, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_grant'

        class Handoff(models.Model):
            desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_handoff'

        self.Desk, self.Sheet = Desk, Sheet
        self.Grant, self.Handoff = Grant, Handoff
        cm = _tables(Desk, Sheet, Grant, Handoff)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        _add_user_column(
            self, User, 'zone', models.CharField(max_length=20, null=True),
        )
        self.change = _permission(Sheet, 'change_samesheet')
        self.code = 'trusts_tests.change_samesheet'
        self.ada = User.objects.create_user('same-ada', password='x')
        self.bea = User.objects.create_user('same-bea', password='x')
        self.ada.zone = 'east'
        self.bea.zone = 'east'
        self.ada.via_manager = self.bea
        self.ada.save()
        self.bea.save()

    def _predicate(self):
        return lambda user, permission, content: (
            (user.zone == content.region) & (content.mark == 'yes')
        )

    def _register(self, name, *, along=None, delegate=False, via=None):
        handle = compiler(path='tests.core.via-same-%s' % name)
        handle.add_named_filter(self.Sheet, 'kept', self._predicate())
        grant = dict(
            trust=self.Grant, user='user', permission='permission',
            content='desk__sheets',
        )
        if along is not None:
            grant['along'] = along
        if via is not None and not delegate:
            grant['via'] = via
        handle.register(**grant)
        if delegate:
            hand = dict(
                trust=self.Handoff, delegate='delegate', sponsor='sponsor',
                content='desk__sheets',
            )
            if along is not None:
                hand['along'] = along
            if via is not None:
                hand['via'] = via
            handle.register(**hand)
        return handle

    def _answers(self, handle, user, sheet):
        filtered = '%s:kept' % self.code
        with _listed(handle):
            has = user.has_perm(filtered, sheet)
            permitted = set(self.Sheet.objects.permitted(
                self.code, user, conditions=('kept',),
            ).values_list('pk', flat=True))
            reached = set(sheet.get_permitted_users(filtered).values_list(
                'pk', flat=True,
            ))
            listed = set(filter_by_permitted_content(
                self.Desk.objects.all(), user, self.change,
                content=self.Sheet, conditions=('kept',),
            ).values_list('pk', flat=True))

            @authorization_required(self.Sheet, self.code, ('kept',))
            def view(request, pk):
                return 'ok'

            try:
                view(_request(user), pk=sheet.pk)
                guarded = True
            except PermissionDenied:
                guarded = False
            complete = self.code in user.get_all_permissions(sheet)
            grouped = self.code in user.get_group_permissions(sheet)
        return {
            'has_perm': has,
            'permitted': sheet.pk in permitted,
            'get_permitted_users': user.pk in reached,
            'authorization_required': guarded,
            'listed': listed,
            'get_all_permissions': complete,
            'get_group_permissions': grouped,
        }

    def _expect_row(self, handle, user, sheet, allowed, listed):
        answers = self._answers(handle, user, sheet)
        filtered = {
            key: answers[key]
            for key in (
                'has_perm', 'permitted', 'get_permitted_users',
                'authorization_required',
            )
        }
        self.assertEqual(set(filtered.values()), {allowed}, answers)
        self.assertEqual(answers['listed'], listed, answers)
        # Unfiltered inquiries. Not an oracle for the named filter.
        self.assertIs(answers['get_all_permissions'], True, answers)
        self.assertIs(answers['get_group_permissions'], False, answers)

    def test_two_rows_and_split_witness_agree(self):
        parent = self.Desk.objects.create()
        child = self.Desk.objects.create(parent=parent)
        modes = (
            ('exact', {'via': ('user__via_manager', 1)}, self.ada, self.ada, child, child),
            ('along', {'along': ('desk__parent', 1), 'via': ('user__via_manager', 1)}, self.ada, self.ada, parent, child),
            ('delegate', {'delegate': True, 'via': ('delegate__via_manager', 1)}, self.bea, self.ada, child, child),
            ('sponsor', {'delegate': True, 'via': ('sponsor__via_manager', 1)}, self.bea, self.bea, child, child),
        )
        for name, options, actor, holder, anchor, listed_desk in modes:
            with self.subTest(name=name, case='positive'):
                self.Sheet.objects.all().delete()
                self.Grant.objects.all().delete()
                self.Handoff.objects.all().delete()
                missed = self.Sheet.objects.create(
                    pk=1, region='west', mark='yes', desk=listed_desk,
                )
                kept = self.Sheet.objects.create(
                    pk=2, region='east', mark='yes', desk=listed_desk,
                )
                self.Grant.objects.create(
                    user=holder, desk=anchor, permission=self.change,
                )
                if options.get('delegate'):
                    self.Handoff.objects.create(
                        desk=anchor, delegate=self.bea, sponsor=self.ada,
                    )
                handle = self._register(name + '-yes', **options)
                self._expect_row(handle, actor, missed, False, {listed_desk.pk})
                self._expect_row(handle, actor, kept, True, {listed_desk.pk})
            with self.subTest(name=name, case='split'):
                self.Sheet.objects.all().delete()
                self.Grant.objects.all().delete()
                self.Handoff.objects.all().delete()
                hop_only = self.Sheet.objects.create(
                    pk=1, region='east', mark='no', desk=listed_desk,
                )
                overlay_only = self.Sheet.objects.create(
                    pk=2, region='west', mark='yes', desk=listed_desk,
                )
                self.Grant.objects.create(
                    user=holder, desk=anchor, permission=self.change,
                )
                if options.get('delegate'):
                    self.Handoff.objects.create(
                        desk=anchor, delegate=self.bea, sponsor=self.ada,
                    )
                handle = self._register(name + '-split', **options)
                self._expect_row(handle, actor, hop_only, False, set())
                self._expect_row(handle, actor, overlay_only, False, set())

    def test_ancestor_walk_uses_the_qualifying_sheet(self):
        User = self.User

        class Office(models.Model):
            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_office'

        class Cabinet(models.Model):
            office = models.ForeignKey(
                Office, related_name='cabinets', on_delete=models.CASCADE,
            )
            parent = models.ForeignKey(
                'self', null=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_cabinet'

        class PageQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Page(PermittedUsersMixin, models.Model):
            region = models.CharField(max_length=20)
            mark = models.CharField(max_length=20)
            cabinet = models.ForeignKey(
                Cabinet, related_name='pages', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(PageQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_page'

        class OfficeGrant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_office_grant'

        class PageHandoff(models.Model):
            office = models.ForeignKey(Office, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_same_office_handoff'

        with _tables(Office, Cabinet, Page, OfficeGrant, PageHandoff):
            change = _permission(Page, 'change_samepage')
            code = 'trusts_tests.change_samepage'
            office = Office.objects.create()
            root = Cabinet.objects.create(office=office)
            child = Cabinet.objects.create(office=office, parent=root)
            missed = Page.objects.create(
                pk=1, region='west', mark='yes', cabinet=child,
            )
            kept = Page.objects.create(
                pk=2, region='east', mark='yes', cabinet=child,
            )
            OfficeGrant.objects.create(
                user=self.ada, office=office, permission=change,
            )
            def expect_ancestor(handle, user, page, allowed, offices):
                filtered = '%s:kept' % code
                with _listed(handle):
                    has = user.has_perm(filtered, page)
                    permitted = page.pk in set(Page.objects.permitted(
                        code, user, conditions=('kept',),
                    ).values_list('pk', flat=True))
                    reached = user.pk in set(
                        page.get_permitted_users(filtered).values_list(
                            'pk', flat=True,
                        ),
                    )
                    listed = set(filter_by_permitted_content(
                        Office.objects.all(), user, change,
                        content=Page, conditions=('kept',),
                    ).values_list('pk', flat=True))

                    @authorization_required(Page, code, ('kept',))
                    def view(request, pk):
                        return 'ok'

                    try:
                        view(_request(user), pk=page.pk)
                        guarded = True
                    except PermissionDenied:
                        guarded = False
                    complete = code in user.get_all_permissions(page)
                    grouped = code in user.get_group_permissions(page)
                self.assertEqual(
                    {
                        'has_perm': has,
                        'permitted': permitted,
                        'get_permitted_users': reached,
                        'authorization_required': guarded,
                    },
                    {
                        'has_perm': allowed,
                        'permitted': allowed,
                        'get_permitted_users': allowed,
                        'authorization_required': allowed,
                    },
                )
                self.assertEqual(listed, offices)
                # No ``group=`` on the registration.
                self.assertIs(grouped, False)
                return complete

            handle = compiler(path='tests.core.via-same-ancestor')
            handle.add_named_filter(Page, 'kept', self._predicate())
            handle.register(
                trust=OfficeGrant, user='user', permission='permission',
                content='office__cabinets__pages',
                along=('office__cabinets__parent', 1),
                via=('user__via_manager', 1),
            )
            # Unfiltered: the grant walks to both pages. Not an oracle.
            self.assertIs(
                expect_ancestor(handle, self.ada, missed, False, {office.pk}),
                True,
            )
            self.assertIs(
                expect_ancestor(handle, self.ada, kept, True, {office.pk}),
                True,
            )
            PageHandoff.objects.create(
                office=office, delegate=self.bea, sponsor=self.ada,
            )
            delegated = compiler(path='tests.core.via-same-ancestor-delegate')
            delegated.add_named_filter(Page, 'kept', self._predicate())
            delegated.register(
                trust=OfficeGrant, user='user', permission='permission',
                content='office__cabinets__pages',
                along=('office__cabinets__parent', 1),
            )
            delegated.register(
                trust=PageHandoff, delegate='delegate', sponsor='sponsor',
                content='office__cabinets__pages',
                along=('office__cabinets__parent', 1),
                via=('delegate__via_manager', 1),
            )
            self.assertIs(
                expect_ancestor(
                    delegated, self.bea, missed, False, {office.pk},
                ),
                True,
            )
            self.assertIs(
                expect_ancestor(delegated, self.bea, kept, True, {office.pk}),
                True,
            )
            missed.region = 'east'
            missed.mark = 'no'
            missed.save(update_fields=['region', 'mark'])
            kept.region = 'west'
            kept.mark = 'yes'
            kept.save(update_fields=['region', 'mark'])
            self.assertIs(
                expect_ancestor(handle, self.ada, missed, False, set()), True,
            )
            self.assertIs(
                expect_ancestor(handle, self.ada, kept, False, set()), True,
            )
            self.assertIs(
                expect_ancestor(delegated, self.bea, missed, False, set()),
                True,
            )
            self.assertIs(
                expect_ancestor(delegated, self.bea, kept, False, set()),
                True,
            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PrefixOccurrenceTest(TransactionTestCase):
    """The later copy of a model uses that hop's own candidate.

    ``node`` and ``node__children`` are both ``Node``. A doc on the
    child is not a doc on that child's child.
    """

    def test_later_occurrence_does_not_read_the_earlier_candidate(self):
        User = get_user_model()
        _attach_manager(self, User)

        class Node(models.Model):
            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_occur_node'

            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

        class DocQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Doc(PermittedUsersMixin, models.Model):
            zone = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, related_name='docs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(DocQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_occur_doc'

        class Seat(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'via_occur_seat'

        _add_user_column(
            self, User, 'zone', models.CharField(max_length=20, null=True),
        )
        with _tables(Node, Doc, Seat):
            change = _permission(Doc, 'change_occurdoc')
            code = 'trusts_tests.change_occurdoc'
            ada = User.objects.create_user('occur-ada', password='x')
            ada.zone = 'west'
            ada.save()
            root = Node.objects.create()
            east_child = Node.objects.create(parent=root)
            west_child = Node.objects.create(parent=root)
            grand = Node.objects.create(parent=east_child)
            east_doc = Doc.objects.create(zone='east', node=east_child)
            west_doc = Doc.objects.create(zone='west', node=west_child)
            grand_doc = Doc.objects.create(zone='west', node=grand)
            Seat.objects.create(user=ada, node=root, permission=change)
            handle = compiler(path='tests.core.via-occur-later')
            handle.add_named_filter(
                Doc, 'kept',
                lambda user, permission, content: user.zone == content.zone,
            )
            handle.register(
                trust=Seat, user='user', permission='permission',
                content='node__children__docs',
                via=('user__via_manager', 1),
            )
            # ``node`` sees docs on children of the seat. ``node__children``
            # sees docs on that child. The grandchild doc is a different
            # candidate and must not qualify the east child.
            with _listed(handle):
                has_west = ada.has_perm('%s:kept' % code, west_doc)
                has_east = ada.has_perm('%s:kept' % code, east_doc)
                has_grand = ada.has_perm('%s:kept' % code, grand_doc)
                permitted = set(Doc.objects.permitted(
                    code, ada, conditions=('kept',),
                ).values_list('pk', flat=True))
                reached = set(west_doc.get_permitted_users(
                    '%s:kept' % code,
                ).values_list('pk', flat=True))
                east_reached = set(east_doc.get_permitted_users(
                    '%s:kept' % code,
                ).values_list('pk', flat=True))
                listed = set(filter_by_permitted_content(
                    Node.objects.all(), ada, change,
                    content=Doc, conditions=('kept',),
                ).values_list('pk', flat=True))

                @authorization_required(Doc, code, ('kept',))
                def view(request, pk):
                    return 'ok'

                try:
                    view(_request(ada), pk=west_doc.pk)
                    guarded = True
                except PermissionDenied:
                    guarded = False
                unfiltered_west = code in ada.get_all_permissions(west_doc)
                unfiltered_east = code in ada.get_all_permissions(east_doc)
                unfiltered_grand = code in ada.get_all_permissions(grand_doc)
                grouped = code in ada.get_group_permissions(west_doc)
            self.assertIs(has_west, True)
            self.assertIs(has_east, False)
            self.assertIs(has_grand, False)
            self.assertEqual(permitted, {west_doc.pk})
            self.assertEqual(reached, {ada.pk})
            self.assertEqual(east_reached, set())
            self.assertEqual(listed, {root.pk, west_child.pk})
            self.assertNotIn(east_child.pk, listed)
            self.assertNotIn(grand.pk, listed)
            self.assertIs(guarded, True)
            # Named filters are not applied. The east doc is on the
            # content path, so the codename is present while the
            # filtered inquiries are false. The grandchild is not on
            # the path.
            self.assertIs(unfiltered_west, True)
            self.assertIs(unfiltered_east, True)
            self.assertIs(unfiltered_grand, False)
            self.assertIs(grouped, False)

