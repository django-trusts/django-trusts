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
        orgs = set(scoped_permitted_content(
            self.Org.objects.all(), user, self.change,
            content=self.Desk, registry=catalog,
        ).values_list('name', flat=True))
        allowed = 'desk' in permitted
        self.assertEqual(has, allowed)
        self.assertEqual(held, allowed)
        self.assertEqual(reached, allowed)
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
