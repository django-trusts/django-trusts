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
from django.db import connection, models
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
from trusts.errors import TrustsConfigurationError
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
