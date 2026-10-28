"""``along=`` over a Trust tree.

Two shapes. The grant row reaches the walked Trust in two hops, the
way Zero's ``TrustGroupPermission`` reaches ``Trust`` through
``trustgroup__trust``. And Zero's own one-hop shape: a non-null
parent named ``trust``, a self-parented root, and content and
sub-Trusts sharing that foreign key.

Every surface answers the same question, so each one must agree:
``has_perm`` on an object, ``get_permitted_users``, ``permitted()``,
and ``permissions_for``.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db import models
from django.test import TransactionTestCase
from django.test.utils import isolate_apps

from tests.core.test_issue282 import _handle, _listed, _permission, _tables
from tests.support import built_catalog, scoped_permitted_content
from trusts.models import (
    AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin)


class _TrustQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
    pass


def _surfaces(test, handle, model, code, permission, user, rows):
    """Each surface's answer for every row, keyed by surface name."""
    catalog = built_catalog(handle)
    with _listed(handle):
        listed = set(
            model.objects.permitted(code, user).values_list('pk', flat=True))
        answers = {
            'has_perm': {
                row.pk for row in rows if user.has_perm(code, row)},
            'get_permitted_users': {
                row.pk for row in rows
                if row.get_permitted_users(permission).filter(
                    pk=user.pk).exists()},
            'permitted': listed & {row.pk for row in rows},
            'permissions_for': {
                row.pk for row in rows
                if catalog.permissions_for(
                    user, model.objects.filter(pk=row.pk),
                ).filter(pk=permission.pk).exists()},
        }
    return answers


def _assert_surfaces(test, answers, expected):
    names = {row.pk: str(row) for row in expected['rows']}
    want = {row.pk for row in expected['allowed']}
    for surface, got in answers.items():
        with test.subTest(surface=surface):
            test.assertEqual(
                sorted(names[pk] for pk in got),
                sorted(names[pk] for pk in want),
            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TwoHopWalkSiteTest(TransactionTestCase):
    """The walked node is two hops from the grant row.

    ``TeamGrant -> team -> folders`` reaches the walked Folder through a
    reverse one-to-many gateway, the multi-hop walk site that register
    accepts. (Zero's forward ``trustgroup__trust`` is rejected at
    register.) The Team id equals a Folder id in the other branch.
    Comparing the grant's team column with Folder ids would grant there.

    a(team T) -> a_child -> a_past ; other -> other_child (team U)
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Team(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att2_team'

        class Folder(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            team = models.ForeignKey(
                Team, related_name='folders', on_delete=models.CASCADE)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE)
            objects = models.Manager.from_queryset(_TrustQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att2_folder'

            def __str__(self):
                return self.title

        class TeamGrant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            user = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att2_teamgrant'

        self.Folder = Folder
        cm = _tables(Team, Folder, TeamGrant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Folder, 'change_folder')
        self.code = 'trusts_tests.change_folder'
        self.alice = User.objects.create_user('att2-alice', password='x')
        granted = Team.objects.create(pk=20, title='T')
        unrelated = Team.objects.create(pk=30, title='U')
        a = Folder.objects.create(pk=10, title='a', team=granted)
        a_child = Folder.objects.create(
            pk=11, title='a_child', team=unrelated, parent=a)
        Folder.objects.create(
            pk=12, title='a_past', team=unrelated, parent=a_child)
        other = Folder.objects.create(pk=20, title='other', team=unrelated)
        Folder.objects.create(
            pk=21, title='other_child', team=unrelated, parent=other)
        TeamGrant.objects.create(
            team=granted, user=self.alice, permission=self.change)
        self.rows = list(Folder.objects.order_by('pk'))
        self.allowed = [a, a_child]
        self.handle = _handle('tests.core.along-two-hop-walk-site')
        self.handle.register(
            trust=TeamGrant,
            user='user',
            permission='permission',
            content='team__folders',
            along=('team__folders__parent', 1),
        )

    def test_every_surface_grants_the_walk_from_the_team_folders(self):
        answers = _surfaces(
            self, self.handle, self.Folder, self.code, self.change,
            self.alice, self.rows)
        _assert_surfaces(self, answers, {
            'rows': self.rows, 'allowed': self.allowed})

    def test_surfaces_agree(self):
        answers = _surfaces(
            self, self.handle, self.Folder, self.code, self.change,
            self.alice, self.rows)
        named = {
            surface: sorted(str(row) for row in self.rows if row.pk in got)
            for surface, got in answers.items()}
        self.assertEqual(len({tuple(v) for v in named.values()}), 1, named)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class TwoHopDelegationWalkTest(TransactionTestCase):
    """The delegation row walks the same two hops as the grant.

    ``TeamDelegation -> team -> folders`` is the anchor. The sponsor's
    ordinary grant walks that path too. The Team id equals a Folder id
    in the other branch, so reading ``team_id`` as a Folder id would
    hand the delegate the colliding branch.
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Team(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att3_team'

        class Folder(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            team = models.ForeignKey(
                Team, related_name='folders', on_delete=models.CASCADE)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE)
            objects = models.Manager.from_queryset(_TrustQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att3_folder'

            def __str__(self):
                return self.title

        class TeamGrant(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            user = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att3_teamgrant'

        class TeamDelegation(models.Model):
            team = models.ForeignKey(Team, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE)
            sponsor = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att3_teamdelegation'

        self.Folder = Folder
        cm = _tables(Team, Folder, TeamGrant, TeamDelegation)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Folder, 'change_folder')
        self.code = 'trusts_tests.change_folder'
        self.sponsor = User.objects.create_user('att3-sponsor', password='x')
        self.alice = User.objects.create_user('att3-alice', password='x')
        granted = Team.objects.create(pk=20, title='T')
        unrelated = Team.objects.create(pk=30, title='U')
        a = Folder.objects.create(pk=10, title='a', team=granted)
        a_child = Folder.objects.create(
            pk=11, title='a_child', team=unrelated, parent=a)
        Folder.objects.create(
            pk=12, title='a_past', team=unrelated, parent=a_child)
        other = Folder.objects.create(pk=20, title='other', team=unrelated)
        Folder.objects.create(
            pk=21, title='other_child', team=unrelated, parent=other)
        TeamGrant.objects.create(
            team=granted, user=self.sponsor, permission=self.change)
        TeamDelegation.objects.create(
            team=granted, delegate=self.alice, sponsor=self.sponsor)
        self.rows = list(Folder.objects.order_by('pk'))
        self.allowed = [a, a_child]
        self.handle = _handle('tests.core.along-two-hop-delegation')
        self.handle.register(
            trust=TeamGrant,
            user='user',
            permission='permission',
            content='team__folders',
            along=('team__folders__parent', 1),
        )
        self.handle.register(
            trust=TeamDelegation,
            delegate='delegate',
            sponsor='sponsor',
            content='team__folders',
            along=('team__folders__parent', 1),
        )

    def test_delegate_walk_follows_the_team_folders(self):
        answers = _surfaces(
            self, self.handle, self.Folder, self.code, self.change,
            self.alice, self.rows)
        _assert_surfaces(self, answers, {
            'rows': self.rows, 'allowed': self.allowed})


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ZeroShapedTrustWalkTest(TransactionTestCase):
    """Zero's Trust: ``trust`` is a non-null self-FK and the root is its own parent.

    Content and sub-Trusts share ``trust``. A grant on a Trust covers
    the content in it, and a sub-Trust is content of its parent Trust.
    ``along=('trust__trust', 2)`` walks toward children.

    root(self) -> mid -> child -> grand -> past ; root -> sibling
    """

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Trust(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            trust = models.ForeignKey(
                'self', related_name='trusts_tests_trust_content',
                on_delete=models.CASCADE)
            objects = models.Manager.from_queryset(_TrustQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att0_trust'

            def __str__(self):
                return self.title

        class Doc(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            trust = models.ForeignKey(
                Trust, related_name='trusts_tests_doc_content',
                on_delete=models.CASCADE)
            objects = models.Manager.from_queryset(_TrustQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att0_doc'

            def __str__(self):
                return self.title

        class TrustUserPermission(models.Model):
            trust = models.ForeignKey(
                Trust, related_name='trustees', on_delete=models.CASCADE)
            entity = models.ForeignKey(
                get_user_model(), related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'att0_tup'

        self.Trust, self.Doc = Trust, Doc
        cm = _tables(Trust, Doc, TrustUserPermission)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change_trust = _permission(Trust, 'change_trust')
        self.change_doc = _permission(Doc, 'change_doc')
        self.alice = User.objects.create_user('att0-alice', password='x')
        self.bob = User.objects.create_user('att0-bob', password='x')

        root = Trust(pk=1000, title='root', trust_id=1000)
        root.save()
        self.root = root
        self.mid = Trust.objects.create(title='mid', trust=root)
        self.child = Trust.objects.create(title='child', trust=self.mid)
        self.grand = Trust.objects.create(title='grand', trust=self.child)
        self.past = Trust.objects.create(title='past', trust=self.grand)
        self.sibling = Trust.objects.create(title='sibling', trust=root)
        self.trusts = [self.root, self.mid, self.child, self.grand, self.past, self.sibling]
        self.docs = {
            t.title: Doc.objects.create(title='doc@' + t.title, trust=t)
            for t in self.trusts
        }
        for permission in (self.change_trust, self.change_doc):
            TrustUserPermission.objects.create(
                trust=self.mid, entity=self.alice, permission=permission)
            TrustUserPermission.objects.create(
                trust=root, entity=self.bob, permission=permission)
        self.handle = _handle('tests.core.along-trust-tree-zero')
        for model in (Doc, Trust):
            self.handle.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content='trust__%s' % Trust._meta.get_field('trust').remote_field.get_accessor_name()
                if model is Trust else 'trust__trusts_tests_doc_content',
                along=('trust__trust', 2),
            )

    def _docs(self, *titles):
        return [self.docs[t] for t in titles]

    def test_mid_grant_covers_its_content_and_descendants_within_bound(self):
        answers = _surfaces(
            self, self.handle, self.Doc, 'trusts_tests.change_doc',
            self.change_doc, self.alice, list(self.docs.values()))
        _assert_surfaces(self, answers, {
            'rows': list(self.docs.values()),
            'allowed': self._docs('mid', 'child', 'grand')})

    def test_mid_grant_covers_sub_trusts_not_parent_or_sibling(self):
        # A sub-Trust is content of its parent, so Trust X is covered
        # when X.trust is in the walk {mid, child, grand}.
        answers = _surfaces(
            self, self.handle, self.Trust, 'trusts_tests.change_trust',
            self.change_trust, self.alice, self.trusts)
        _assert_surfaces(self, answers, {
            'rows': self.trusts,
            'allowed': [self.child, self.grand, self.past]})

    def test_root_grant_does_not_run_past_the_bound_through_the_self_loop(self):
        answers = _surfaces(
            self, self.handle, self.Doc, 'trusts_tests.change_doc',
            self.change_doc, self.bob, list(self.docs.values()))
        _assert_surfaces(self, answers, {
            'rows': list(self.docs.values()),
            'allowed': self._docs('root', 'mid', 'sibling', 'child')})

    def test_root_grant_on_trusts_and_exclude_root(self):
        answers = _surfaces(
            self, self.handle, self.Trust, 'trusts_tests.change_trust',
            self.change_trust, self.bob, self.trusts)
        _assert_surfaces(self, answers, {
            'rows': self.trusts,
            'allowed': [self.root, self.mid, self.sibling, self.child, self.grand]})
        # Zero's create-under-Trust list: the permitted-content prefix,
        # then ``exclude(pk=ROOT_PK)``.
        under = scoped_permitted_content(
            self.Trust.objects.all(), self.bob, self.change_doc,
            content=self.Doc, registry=built_catalog(self.handle))
        self.assertEqual(
            sorted(t.title for t in under),
            ['child', 'mid', 'root', 'sibling'])
        self.assertEqual(
            sorted(t.title for t in under.exclude(pk=self.root.pk)),
            ['child', 'mid', 'sibling'])
        mine = scoped_permitted_content(
            self.Trust.objects.all(), self.alice, self.change_doc,
            content=self.Doc, registry=built_catalog(self.handle))
        self.assertEqual(sorted(t.title for t in mine), ['child', 'grand', 'mid'])
