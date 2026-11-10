"""Path conditions on ``along=`` and ``via=``.

A step is taken only when the condition on the row being stepped from
is true. False and NULL stop that step. The grant's own row is depth 0.
"""

from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TransactionTestCase, override_settings
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


class _StepBackend(TrustModelBackendMixin, ModelBackend):
    pass


@contextmanager
def _listed(handle):
    with published_class_catalog(_StepBackend, handle):
        with override_settings(
            AUTHENTICATION_BACKENDS=(
                'tests.core.test_along_condition._StepBackend',
            ),
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


def _bind_m2m(model, name, related):
    field = model._meta.get_field(name)
    if not hasattr(field, 'm2m_field_name'):
        field.contribute_to_related_class(related, field.remote_field)


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongConditionTest(TransactionTestCase):
    """Object, queryset, users, policy, delegation, and group walks agree."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            inherits = models.BooleanField(null=True)
            forced = models.BooleanField(null=True)
            rank = models.IntegerField(default=0)

            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_node'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_grant'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_group_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_delegation'

        self.Node = Node
        self.Sheet = Sheet
        self.Grant = Grant
        self.GroupGrant = GroupGrant
        self.Delegation = Delegation
        self._cm = _tables(Node, Sheet, Grant, GroupGrant, Delegation)
        self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        self.change = _permission(Sheet, 'change_acond')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.nodes = {}
        self.sheets = {}
        # A → B(false) → C(true), A → D(null, rank 2), and outsider E.
        self._node('A', inherits=True)
        self._node('B', parent='A', inherits=False)
        self._node('C', parent='B', inherits=True)
        self._node('D', parent='A', inherits=None, rank=2)
        self._node('E', inherits=True)
        self.alice = User.objects.create_user('acond-alice', password='x')
        self.bob = User.objects.create_user('acond-bob', password='x')
        self.sponsor = User.objects.create_user('acond-sponsor', password='x')
        self.delegate = User.objects.create_user('acond-delegate', password='x')
        self.editors = Group.objects.create(name='acond-editors')
        self.editors.permissions.add(self.change)
        self.editors.user_set.add(self.bob)

    def _node(self, title, parent=None, inherits=None, rank=0):
        node = self.Node.objects.create(
            title=title,
            parent=None if parent is None else self.nodes[parent],
            inherits=inherits,
            rank=rank,
        )
        self.nodes[title] = node
        self.sheets[title] = self.Sheet.objects.create(title=title, node=node)
        return node

    def _grant(self, user, title):
        return self.Grant.objects.create(
            user=user, node=self.nodes[title], permission=self.change,
        )

    def _open(self, name, along, **extra):
        handle = compiler(path='tests.core.along-condition.%s' % name)
        kwargs = dict(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='node__sheets',
            along=along,
        )
        kwargs.update(extra)
        handle.register(**kwargs)
        return handle

    def _agree(self, handle, user, titles, *, group=False):
        want = set(titles)
        catalog = built_catalog(handle)
        with _listed(handle):
            with self.assertNumQueries(1):
                permitted = set(
                    self.Sheet.objects.permitted(
                        self.code, user,
                    ).values_list('title', flat=True),
                )
            self.assertEqual(permitted, want)
            for sheet in self.Sheet.objects.all():
                allowed = sheet.title in want
                self.assertEqual(
                    user.has_perm(self.code, sheet), allowed, sheet.title,
                )
                holders = set(sheet.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                self.assertEqual(user.pk in holders, allowed, sheet.title)
                self.assertEqual(
                    self.code in user.get_all_permissions(sheet),
                    allowed,
                    sheet.title,
                )
                if group:
                    self.assertEqual(
                        self.code in user.get_group_permissions(sheet),
                        allowed,
                        sheet.title,
                    )
            listed = scoped_permitted_content(
                self.Node.objects.all(), user, self.change,
                content=self.Sheet, registry=catalog,
            )
            with self.assertNumQueries(1):
                nodes = set(listed.values_list('title', flat=True))
            self.assertEqual(nodes, want)
            compiled = str(
                self.Sheet.objects.permitted(self.code, user).query,
            )
        self.assertIn('WITH RECURSIVE', compiled.upper())
        self.assertNotIn('IS NOT TRUE', compiled.upper())

    def test_string_path_and_path_lambda_reach_the_same_rows(self):
        self._grant(self.alice, 'A')
        cases = (
            ('string', ('node__parent', 8), {'A', 'B', 'C', 'D'}),
            ('lambda', (lambda t: t.node.parent, 8), {'A', 'B', 'C', 'D'}),
        )
        for name, along, titles in cases:
            with self.subTest(name=name):
                self._agree(self._open(name, along), self.alice, titles)

    def test_condition_stops_on_false_and_null_and_keeps_an_independent_grant(self):
        self._grant(self.alice, 'A')
        along = (lambda t: t.node.inherits & t.node.parent, 8)
        handle = self._open('inherits', along)
        with self.subTest('false and null stop the step'):
            self._agree(handle, self.alice, {'A'})
        self.nodes['B'].inherits = True
        self.nodes['B'].save(update_fields=['inherits'])
        self.nodes['C'].inherits = False
        self.nodes['C'].save(update_fields=['inherits'])
        with self.subTest('true continues and the next false stops'):
            self._agree(handle, self.alice, {'A', 'B'})
        self.nodes['C'].inherits = None
        self.nodes['C'].save(update_fields=['inherits'])
        self._grant(self.alice, 'C')
        with self.subTest('a grant on the row still applies'):
            self._agree(handle, self.alice, {'A', 'B', 'C'})

    def test_or_and_comparison_use_three_valued_sql(self):
        self._grant(self.alice, 'A')
        handle = self._open('either', (
            lambda t: (t.node.inherits | (t.node.rank >= 2)) & t.node.parent,
            8,
        ))
        # B is false and rank 0. D is null and rank 2, so the comparison is true.
        self._agree(handle, self.alice, {'A', 'D'})
        self.alice.is_active = False
        self.alice.save(update_fields=['is_active'])
        self._agree(handle, self.alice, set())

    def test_parent_link_condition_is_the_same_edge_either_way(self):
        # Downward. B's parent link is followed, so B.inherits gates B
        # even though A.inherits is false.
        self.nodes['A'].inherits = False
        self.nodes['A'].save(update_fields=['inherits'])
        self.nodes['B'].inherits = True
        self.nodes['B'].save(update_fields=['inherits'])
        self.nodes['C'].inherits = False
        self.nodes['C'].save(update_fields=['inherits'])
        self._grant(self.alice, 'A')
        down = self._open('edge-down', (
            lambda t: t.node.inherits & t.node.parent, 8,
        ))
        with self.subTest('downward checks the child that points at its parent'):
            self._agree(down, self.alice, {'A', 'B'})

        # Upward. Leaving B for A follows B's parent link, so B.inherits
        # stops that step even though A.inherits is true.
        self.Grant.objects.all().delete()
        self.nodes['A'].inherits = True
        self.nodes['A'].save(update_fields=['inherits'])
        self.nodes['B'].inherits = False
        self.nodes['B'].save(update_fields=['inherits'])
        self.nodes['C'].inherits = True
        self.nodes['C'].save(update_fields=['inherits'])
        self._grant(self.alice, 'C')
        up = self._open('edge-up', (
            lambda t: t.node.inherits & t.node.children, 8,
        ))
        with self.subTest('upward checks that same child'):
            self._agree(up, self.alice, {'C', 'B'})

        self.Grant.objects.all().delete()
        self._grant(self.sponsor, 'C')
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, node=self.nodes['C'],
        )
        delegated = compiler(path='tests.core.along-condition.edge-deleg')
        delegated.register(
            trust=self.Grant, user='user', permission='permission',
            content='node__sheets', along=('node__children', 8),
        )
        delegated.register(
            trust=self.Delegation, delegate='delegate', sponsor='sponsor',
            content='node__sheets',
            along=(lambda t: t.node.inherits & t.node.children, 8),
        )
        with self.subTest('sponsor walk and delegation walk share the edge'):
            self._agree(delegated, self.sponsor, {'A', 'B', 'C'})
            self._agree(delegated, self.delegate, {'B', 'C'})

    def test_group_delegation_and_catalogs_agree(self):
        self._grant(self.sponsor, 'A')
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, node=self.nodes['A'],
        )
        sponsor_cut = compiler(path='tests.core.along-condition.sponsor')
        sponsor_cut.register(
            trust=self.Grant, user='user', permission='permission',
            content='node__sheets',
            along=(lambda t: t.node.inherits & t.node.parent, 8),
        )
        sponsor_cut.register(
            trust=self.Delegation, delegate='delegate', sponsor='sponsor',
            content='node__sheets',
        )
        with self.subTest('sponsor condition limits the delegate'):
            self._agree(sponsor_cut, self.sponsor, {'A'})
            self._agree(sponsor_cut, self.delegate, {'A'})
        opened = compiler(path='tests.core.along-condition.delegate-cut')
        opened.register(
            trust=self.Grant, user='user', permission='permission',
            content='node__sheets', along=('node__parent', 8),
        )
        opened.register(
            trust=self.Delegation, delegate='delegate', sponsor='sponsor',
            content='node__sheets',
            along=(lambda t: t.node.inherits & t.node.parent, 8),
        )
        with self.subTest('delegation condition intersects the sponsor walk'):
            self._agree(opened, self.sponsor, {'A', 'B', 'C', 'D'})
            self._agree(opened, self.delegate, {'A'})
        grouped = compiler(path='tests.core.along-condition.group')
        grouped.register(
            trust=self.GroupGrant, user='group__user', group='group',
            content='node__sheets',
            along=(lambda t: t.node.inherits & t.node.parent, 8),
        )
        self.GroupGrant.objects.create(group=self.editors, node=self.nodes['A'])
        with self.subTest('group grant uses the same condition'):
            self._agree(grouped, self.bob, {'A'}, group=True)
        stop = built_catalog(self._open('catalog-stop', (
            lambda t: t.node.inherits & t.node.parent, 8,
        )))
        wide = built_catalog(self._open('catalog-wide', ('node__parent', 8)))
        with self.subTest('each catalog answers from its own registration'):
            self.assertTrue(stop.has_perm(
                self.sponsor, self.code, self.sheets['A'],
            ))
            self.assertFalse(stop.has_perm(
                self.sponsor, self.code, self.sheets['C'],
            ))
            self.assertTrue(wide.has_perm(
                self.sponsor, self.code, self.sheets['C'],
            ))

    def test_policy_sql_carries_the_condition(self):
        handle = self._open('policy', (
            lambda t: t.node.inherits & t.node.parent, 4,
        ))
        text = render_configured_policy(handle).decode()
        self.assertIn('WITH RECURSIVE', text)
        self.assertIn('inherits', text)
        self.assertIn('condition: "inherits"', text)
        self.assertIn('__along_cond', text)
        self.assertNotIn('IS NOT TRUE', text)
        self.assertNotIn('reset:', text)

    def test_register_rejects_a_third_element_and_a_bad_condition(self):
        rejects = (
            (('node__parent', 8, 'inherits'), 'pair'),
            (('node__parent',), 'pair'),
            ((lambda t: t.node.inherits, 8), 'resolvable path'),
            ((lambda t: t.node.parent & t.node.children, 8), 'exactly one'),
            ((lambda t: t.user.is_active & t.node.parent, 8), 'walked node'),
            ((lambda t: t.node.title & t.node.parent, 8), 'boolean'),
            ((lambda t, extra: t.node.parent, 8), 'exactly one'),
        )
        for index, (along, fragment) in enumerate(rejects):
            with self.subTest(index=index):
                handle = compiler(
                    path='tests.core.along-condition.reject-%s' % index,
                )
                with self.assertNumQueries(0):
                    with self.assertRaisesRegex(TrustsConfigurationError, fragment):
                        handle.register(
                            trust=self.Grant, user='user',
                            permission='permission', content='node__sheets',
                            along=along,
                        )
                self.assertEqual(handle.records, ())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaConditionTest(TransactionTestCase):
    """``via=`` uses the same path, bound, and condition as ``along=``."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Team(models.Model):
            name = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='subgroups',
                on_delete=models.CASCADE,
            )
            inherits = models.BooleanField(null=True)
            members = models.ManyToManyField(User, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_team'

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
                db_table = 'acond_job'

        class TeamGrant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_team_grant'

        self.Team = Team
        self.Job = Job
        self.TeamGrant = TeamGrant
        self._cm = _tables(Team, Job, TeamGrant)
        self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        _bind_m2m(Team, 'members', User)
        self.change = _permission(Job, 'change_acond_job')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.org = Team.objects.create(name='org', inherits=True)
        self.unit = Team.objects.create(
            name='unit', parent=self.org, inherits=False,
        )
        self.desk = Team.objects.create(
            name='desk', parent=self.unit, inherits=True,
        )
        self.job = Job.objects.create(name='job', team=self.org)
        self.alice = User.objects.create_user('acond-via-alice', password='x')
        self.cara = User.objects.create_user('acond-via-cara', password='x')
        self.ned = User.objects.create_user('acond-via-ned', password='x')
        self.org.members.add(self.alice)
        self.unit.members.add(self.cara)
        self.desk.members.add(self.ned)
        TeamGrant.objects.create(team=self.org, permission=self.change)

    def _open(self, name, via):
        handle = compiler(path='tests.core.along-condition.via-%s' % name)
        handle.register(
            trust=self.TeamGrant,
            user='team__members',
            permission='permission',
            content='team__jobs',
            via=via,
        )
        return handle

    def _held(self, handle, user):
        with _listed(handle):
            if not user.has_perm(self.code, self.job):
                return False
            return user.pk in set(
                self.job.get_permitted_users(self.change).values_list(
                    'pk', flat=True,
                )
            )

    def test_via_condition_matches_along(self):
        stopped = self._open('stop', (
            lambda t: t.team.inherits & t.team.parent, 8,
        ))
        opened = self._open('open', ('team__parent', 8))
        with self.subTest('false stops the next team'):
            self.assertIs(self._held(stopped, self.alice), True)
            self.assertIs(self._held(stopped, self.cara), False)
            self.assertIs(self._held(stopped, self.ned), False)
        self.unit.inherits = None
        self.unit.save(update_fields=['inherits'])
        with self.subTest('null stops the next team'):
            self.assertIs(self._held(stopped, self.cara), False)
        self.unit.inherits = True
        self.unit.save(update_fields=['inherits'])
        with self.subTest('true continues'):
            self.assertIs(self._held(stopped, self.cara), True)
            self.assertIs(self._held(stopped, self.ned), True)
        with self.subTest('a walk without a condition is unchanged'):
            self.unit.inherits = False
            self.unit.save(update_fields=['inherits'])
            self.assertIs(self._held(opened, self.cara), True)
            self.assertIs(self._held(opened, self.ned), True)
        desk_job = self.Job.objects.create(name='desk-job', team=self.desk)
        self.TeamGrant.objects.create(team=self.desk, permission=self.change)
        upward = self._open('up', (
            lambda t: t.team.inherits & t.team.subgroups, 8,
        ))
        with self.subTest('upward via checks the team whose parent link is followed'):
            # desk.inherits is true, so the step to unit is taken.
            # unit.inherits is false, so the step to org is not.
            with _listed(upward):
                self.assertIs(self.ned.has_perm(self.code, desk_job), True)
                self.assertIs(self.cara.has_perm(self.code, desk_job), True)
                self.assertIs(self.alice.has_perm(self.code, desk_job), False)
                holders = set(desk_job.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
            self.assertEqual(holders, {self.ned.pk, self.cara.pk})
        with self.subTest('via rejects a third element'):
            handle = compiler(path='tests.core.along-condition.via-triple')
            with self.assertNumQueries(0):
                with self.assertRaisesRegex(TrustsConfigurationError, 'pair'):
                    handle.register(
                        trust=self.TeamGrant,
                        user='team__members',
                        permission='permission',
                        content='team__jobs',
                        via=('team__parent', 8, 'inherits'),
                    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongContainsTest(TransactionTestCase):
    """``.contains()`` on the walked node is SQL in the hop."""

    def test_membership_is_true_only_when_the_row_holds_the_member(self):
        User = get_user_model()

        class Tag(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_tag'

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField(Tag, related_name='nodes')
            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_tag_node'

        class Grant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'acond_tag_grant'

        with _tables(Tag, Node, Grant):
            _bind_m2m(Node, 'tags', Tag)
            change = _permission(Node, 'change_acond_tag')
            code = '%s.%s' % (
                change.content_type.app_label, change.codename,
            )
            kept = Tag.objects.create(name='kept')
            root = Node.objects.create(title='A')
            child = Node.objects.create(title='B', parent=root)
            leaf = Node.objects.create(title='C', parent=child)
            root.tags.add(kept)
            alice = User.objects.create_user('acond-tag-alice', password='x')
            Grant.objects.create(user=alice, node=root, permission=change)
            handle = compiler(path='tests.core.along-condition.contains')
            handle.register(
                trust=Grant, user='user', permission='permission',
                content='node',
                along=(lambda t: t.node.tags.contains(kept.pk) & t.node.parent, 8),
            )
            with _listed(handle):
                held = set(
                    Node.objects.permitted(code, alice).values_list(
                        'title', flat=True,
                    )
                )
            self.assertEqual(held, {'A'})
            child.tags.add(kept)
            leaf.tags.add(kept)
            with _listed(handle):
                held = set(
                    Node.objects.permitted(code, alice).values_list(
                        'title', flat=True,
                    )
                )
            self.assertEqual(held, {'A', 'B', 'C'})
            child.tags.clear()
            with _listed(handle):
                held = set(
                    Node.objects.permitted(code, alice).values_list(
                        'title', flat=True,
                    )
                )
            self.assertEqual(held, {'A'})


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class MembershipIdentityTest(TransactionTestCase):
    """A member is the related row's PK, even when the FK stores ``to_field``.

    Swapped keys: the decoy row's stored key equals the wanted row's PK,
    and the wanted row's key equals the decoy's PK. Only the wanted row
    may satisfy the condition.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Tag(models.Model):
            key = models.IntegerField(unique=True, db_column='tag_key')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_tag'

        class MemFar(models.Model):
            node = models.ForeignKey(
                'Node', on_delete=models.CASCADE, related_name='+',
            )
            tag = models.ForeignKey(
                Tag, to_field='key', db_column='link_tag',
                on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_far'

        class MemNear(models.Model):
            node = models.ForeignKey(
                'Node', to_field='code', db_column='link_node',
                on_delete=models.CASCADE, related_name='+',
            )
            tag = models.ForeignKey(
                Tag, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_near'

        class MemBoth(models.Model):
            node = models.ForeignKey(
                'Node', to_field='code', db_column='link_node',
                on_delete=models.CASCADE, related_name='+',
            )
            tag = models.ForeignKey(
                Tag, to_field='key', db_column='link_tag',
                on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_both'

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            code = models.IntegerField(unique=True, db_column='node_code')
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            badge = models.ForeignKey(
                Tag, to_field='key', null=True, db_column='badge_key',
                on_delete=models.CASCADE, related_name='+',
            )
            owner = models.ForeignKey(
                User, to_field='username', null=True, db_column='owner_name',
                on_delete=models.CASCADE, related_name='+',
            )
            tags_far = models.ManyToManyField(
                Tag, through=MemFar, through_fields=('node', 'tag'),
                related_name='+',
            )
            tags_near = models.ManyToManyField(
                Tag, through=MemNear, through_fields=('node', 'tag'),
                related_name='+',
            )
            tags_both = models.ManyToManyField(
                Tag, through=MemBoth, through_fields=('node', 'tag'),
                related_name='+',
            )
            tags_auto = models.ManyToManyField(Tag, related_name='auto_nodes')
            members = models.ManyToManyField(User, related_name='+')
            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_node'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_grant'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_group_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_delegation'

        class ViaGrant(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'mem_via_grant'

        self.Node = Node
        self.Sheet = Sheet
        self.Grant = Grant
        self.GroupGrant = GroupGrant
        self.Delegation = Delegation
        self.ViaGrant = ViaGrant
        models_ = (
            Tag, Node, MemFar, MemNear, MemBoth, Sheet, Grant, GroupGrant,
            Delegation, ViaGrant,
        )
        self._cm = _tables(*models_)
        self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        for name in ('tags_far', 'tags_near', 'tags_both', 'tags_auto', 'members'):
            _bind_m2m(Node, name, Tag if name != 'members' else User)
        self.change = _permission(Sheet, 'change_mem')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        # wanted pk=1 key=2, decoy pk=2 key=1. A pk=1 code=2, B pk=2 code=1.
        self.wanted = Tag.objects.create(pk=1, key=2)
        self.decoy = Tag.objects.create(pk=2, key=1)
        self.nodes = {}
        self.sheets = {}
        self.nodes['A'] = Node.objects.create(pk=1, code=2, title='A')
        self.nodes['B'] = Node.objects.create(
            pk=2, code=1, title='B', parent=self.nodes['A'],
        )
        for title, node in self.nodes.items():
            self.sheets[title] = Sheet.objects.create(title=title, node=node)
        self.alice = User.objects.create_user('mem-alice', password='x')
        self.bob = User.objects.create_user('mem-bob', password='x')
        self.cara = User.objects.create_user('mem-cara', password='x')
        self.sponsor = User.objects.create_user('mem-sponsor', password='x')
        self.delegate = User.objects.create_user('mem-delegate', password='x')
        self.editors = Group.objects.create(name='mem-editors')
        self.editors.permissions.add(self.change)
        self.editors.user_set.add(self.bob)
        self.nodes['A'].members.add(self.alice)
        self.nodes['B'].members.add(self.cara)
        # username is the FK target. Decoy username '1001' equals the
        # wanted user's pk, and the wanted username equals the decoy pk.
        self.wanted_user = User.objects.create_user(
            username='1002', password='x', pk=1001,
        )
        self.decoy_user = User.objects.create_user(
            username='1001', password='x', pk=1002,
        )

    def _clear(self):
        self.Node.tags_far.through.objects.all().delete()
        self.Node.tags_near.through.objects.all().delete()
        self.Node.tags_both.through.objects.all().delete()
        self.Node.tags_auto.through.objects.all().delete()
        self.Node.objects.update(badge=None, owner=None)
        self.Grant.objects.all().delete()
        self.GroupGrant.objects.all().delete()
        self.Delegation.objects.all().delete()
        self.ViaGrant.objects.all().delete()

    def _along(self, name, condition):
        handle = compiler(path='tests.core.mem.%s' % name)
        handle.register(
            trust=self.Grant, user='user', permission='permission',
            content='node__sheets',
            along=(lambda t, condition=condition: condition(t) & t.node.parent, 4),
        )
        return handle

    def _titles(self, handle, user, *, group=False):
        with _listed(handle):
            permitted = set(self.Sheet.objects.permitted(
                self.code, user,
            ).values_list('title', flat=True))
            forward = {
                sheet.title: user.has_perm(self.code, sheet)
                for sheet in self.Sheet.objects.all()
            }
            reverse = {
                sheet.title: user.pk in set(sheet.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                for sheet in self.Sheet.objects.all()
            }
            enumerated = {
                sheet.title: self.code in user.get_all_permissions(sheet)
                for sheet in self.Sheet.objects.all()
            }
            grouped = None
            if group:
                grouped = {
                    sheet.title: self.code in user.get_group_permissions(sheet)
                    for sheet in self.Sheet.objects.all()
                }
            nodes = set(scoped_permitted_content(
                self.Node.objects.all(), user, self.change,
                content=self.Sheet, registry=built_catalog(handle),
            ).values_list('title', flat=True))
        return permitted, forward, reverse, enumerated, grouped, nodes

    def _expect(self, handle, user, titles, *, group=False):
        permitted, forward, reverse, enumerated, grouped, nodes = self._titles(
            handle, user, group=group,
        )
        self.assertEqual(permitted, set(titles))
        for title, sheet_ok in forward.items():
            self.assertEqual(sheet_ok, title in titles, title)
            self.assertEqual(reverse[title], title in titles, title)
            self.assertEqual(enumerated[title], title in titles, title)
            if grouped is not None:
                self.assertEqual(grouped[title], title in titles, title)
        self.assertEqual(nodes, set(titles))

    def _plant(self, kind, positive):
        child = self.nodes['B']
        parent = self.nodes['A']
        if kind == 'm2m-far':
            child.tags_far.add(self.wanted if positive else self.decoy)
        elif kind == 'm2m-near':
            parent.tags_near.add(self.wanted)
            if positive:
                child.tags_near.add(self.wanted)
        elif kind == 'm2m-both':
            if positive:
                child.tags_both.add(self.wanted)
            else:
                child.tags_both.add(self.decoy)
        elif kind == 'm2m-auto':
            child.tags_auto.add(self.wanted if positive else self.decoy)
        elif kind == 'fk-contains':
            child.badge = self.wanted if positive else self.decoy
            child.save(update_fields=['badge'])
        elif kind == 'fk-eq':
            child.owner = self.wanted_user if positive else self.decoy_user
            child.save(update_fields=['owner'])
        else:
            raise AssertionError(kind)

    def test_swapped_keys_do_not_overgrant(self):
        kinds = (
            'm2m-far', 'm2m-near', 'm2m-both', 'm2m-auto',
            'fk-contains', 'fk-eq',
        )
        for kind in kinds:
            for positive, titles in ((False, {'A'}), (True, {'A', 'B'})):
                with self.subTest(kind=kind, positive=positive):
                    self._clear()
                    self._plant(kind, positive)
                    # The near-side negative attaches the wanted tag to A
                    # only. Both directions must still leave B out.
                    if kind == 'm2m-both' and not positive:
                        self.nodes['A'].tags_both.add(self.wanted)
                    self.Grant.objects.create(
                        user=self.alice, node=self.nodes['A'],
                        permission=self.change,
                    )
                    if kind == 'fk-eq':
                        condition = lambda t: t.node.owner == self.wanted_user
                    elif kind == 'fk-contains':
                        condition = lambda t: t.node.badge.contains(self.wanted.pk)
                    else:
                        attr = {
                            'm2m-far': 'tags_far',
                            'm2m-near': 'tags_near',
                            'm2m-both': 'tags_both',
                            'm2m-auto': 'tags_auto',
                        }[kind]
                        pk = self.wanted.pk
                        condition = lambda t, attr=attr, pk=pk: (
                            getattr(t.node, attr).contains(pk)
                        )
                    handle = self._along('%s-%s' % (kind, positive), condition)
                    self._expect(handle, self.alice, titles)

    def test_far_to_field_agrees_across_entries(self):
        self._clear()
        self.nodes['B'].tags_far.add(self.decoy)
        condition = lambda t: t.node.tags_far.contains(self.wanted.pk)
        self.Grant.objects.create(
            user=self.sponsor, node=self.nodes['A'], permission=self.change,
        )
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, node=self.nodes['A'],
        )
        self.GroupGrant.objects.create(
            group=self.editors, node=self.nodes['A'],
        )
        self.ViaGrant.objects.create(
            node=self.nodes['A'], permission=self.change,
        )
        delegated = compiler(path='tests.core.mem.deleg')
        delegated.register(
            trust=self.Grant, user='user', permission='permission',
            content='node__sheets',
            along=(lambda t: condition(t) & t.node.parent, 4),
        )
        delegated.register(
            trust=self.Delegation, delegate='delegate', sponsor='sponsor',
            content='node__sheets',
            along=(lambda t: condition(t) & t.node.parent, 4),
        )
        grouped = compiler(path='tests.core.mem.group')
        grouped.register(
            trust=self.GroupGrant, user='group__user', group='group',
            content='node__sheets',
            along=(lambda t: condition(t) & t.node.parent, 4),
        )
        via = compiler(path='tests.core.mem.via')
        via.register(
            trust=self.ViaGrant, user='node__members', permission='permission',
            content='node__sheets',
            via=(lambda t: condition(t) & t.node.parent, 4),
        )
        with self.subTest('decoy does not reach the child'):
            self._expect(delegated, self.sponsor, {'A'})
            self._expect(delegated, self.delegate, {'A'})
            self._expect(grouped, self.bob, {'A'}, group=True)
            with _listed(via):
                self.assertIs(
                    self.alice.has_perm(self.code, self.sheets['A']), True,
                )
                self.assertIs(
                    self.cara.has_perm(self.code, self.sheets['A']), False,
                )
                holders = set(self.sheets['A'].get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
            self.assertIn(self.alice.pk, holders)
            self.assertNotIn(self.cara.pk, holders)
        text = render_configured_policy(delegated).decode()
        self.assertIn('mem_tag', text)
        self.assertIn('tag_key', text)
        self.nodes['B'].tags_far.add(self.wanted)
        with self.subTest('wanted member reaches the child'):
            self._expect(delegated, self.sponsor, {'A', 'B'})
            self._expect(delegated, self.delegate, {'A', 'B'})
            self._expect(grouped, self.bob, {'A', 'B'}, group=True)
            with _listed(via):
                self.assertIs(
                    self.cara.has_perm(self.code, self.sheets['A']), True,
                )
