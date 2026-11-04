"""``along=(path, bound, field)`` cuts inherited reach at a true field.

``NULL`` and false inherit. A grant on a stop still applies there and
can continue. A content walk, a delegation walk, and a sponsor walk
each honor the field configured on that walk.
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
from trusts.decorators import authorization_required
from trusts.errors import TrustsConfigurationError
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)


class _ResetBackend(TrustModelBackendMixin, ModelBackend):
    pass


@contextmanager
def _listed(handle):
    with published_class_catalog(_ResetBackend, handle):
        with override_settings(
            AUTHENTICATION_BACKENDS=('tests.core.test_along_reset._ResetBackend',),
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


_OMIT = object()


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ResetRegistrationTest(SimpleTestCase):
    """``register()`` accepts the three placements and rejects the rest."""

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

        class Node(models.Model):
            title = models.CharField(max_length=20)
            rank = models.IntegerField(null=True)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)
            badge = models.OneToOneField(
                Badge, null=True, related_name='owner',
                on_delete=models.CASCADE,
            )
            flags = models.ManyToManyField(Flag, related_name='nodes')
            wide = models.ManyToManyField(Wide, related_name='nodes')
            notes = GenericRelation(Note)

            class Meta:
                app_label = 'trusts_tests'

        class Mark(models.Model):
            reset_inheritance = models.BooleanField(null=True)
            nodes = models.ManyToManyField(Node, related_name='marks')

            class Meta:
                app_label = 'trusts_tests'

        class Link(models.Model):
            parent = models.ForeignKey(
                Node, related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Node, related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class HeldBase(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Held(HeldBase):
            parent = models.ForeignKey(
                Node, related_name='held_children', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Node, related_name='held_parents', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Policy(models.Model):
            node = models.ForeignKey(
                Node, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Portrait(models.Model):
            node = models.OneToOneField(
                Node, related_name='portrait', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        self.Node = Node
        self.Grant = Grant
        self.Delegation = Delegation

    def _register_role(self, role, along):
        handle = compiler()
        if role == 'delegation':
            return handle.register(
                trust=self.Delegation,
                delegate='delegate',
                sponsor='sponsor',
                content='node',
                along=along,
            )
        record = handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='node',
            along=along,
        )
        if role == 'sponsor':
            handle.register(
                trust=self.Delegation,
                delegate='delegate',
                sponsor='sponsor',
                content='node',
                along=('node__parent', 2),
            )
        return record

    def test_two_element_tuple_sets_no_reset(self):
        for role in ('content', 'delegation', 'sponsor'):
            with self.subTest(role=role):
                record = self._register_role(role, ('node__parent', 4))
                self.assertIsNone(record.along.reset)

    def test_allowed_placements_resolve_on_every_walk(self):
        cases = (
            ('node', ('node__parent', 4, 'reset_inheritance'), 'node'),
            (
                'edge',
                ('node__parent_links__parent', 4, 'parent_links__reset_inheritance'),
                'edge',
            ),
            ('m2m', ('node__parent', 4, 'flags__reset_inheritance'), 'any'),
            (
                'reverse-m2m',
                ('node__parent', 4, 'marks__reset_inheritance'),
                'any',
            ),
            (
                'reverse-fk',
                ('node__parent', 4, 'policies__reset_inheritance'),
                'any',
            ),
        )
        for role in ('content', 'delegation', 'sponsor'):
            for name, along, kind in cases:
                with self.subTest(role=role, placement=name):
                    reset = self._register_role(role, along).along.reset
                    self.assertEqual(reset.kind, kind)
                    self.assertEqual(reset.path, along[2])
                    if kind == 'node':
                        field = self.Node._meta.get_field('reset_inheritance')
                        self.assertTrue(field.null)
                        self.assertEqual(reset.column, field.column)
                    elif name == 'm2m':
                        field = self.Node._meta.get_field('flags')
                        self.assertEqual(reset.through_node, field.m2m_column_name())
                        self.assertEqual(reset.far_fk, field.m2m_reverse_name())
                    elif name == 'reverse-m2m':
                        forward = self.Node._meta.get_field('marks').field
                        self.assertEqual(
                            reset.through_node, forward.m2m_reverse_name(),
                        )
                        self.assertEqual(reset.far_fk, forward.m2m_column_name())
                    elif name == 'reverse-fk':
                        fk = self.Node._meta.get_field('policies').field
                        self.assertIsNone(reset.far_table)
                        self.assertEqual(reset.through_node, fk.column)
                        self.assertEqual(reset.column, 'reset_inheritance')
                        self.assertTrue(fk.model._meta.get_field(
                            'reset_inheritance',
                        ).null)

    def test_register_rejects_paths_outside_the_three_placements(self):
        cases = (
            (('node__parent', 4, 'portrait__reset_inheritance'), 'reverse one-to-one'),
            (('node__parent', 4, 'parent__reset_inheritance'), 'forward foreign key'),
            (('node__parent', 4, 'badge__reset_inheritance'), 'forward foreign key'),
            (
                ('node__parent', 4, 'parent__children__reset_inheritance'),
                'one relation',
            ),
            (('node__parent', 4, 'notes__reset_inheritance'), 'generic relation'),
            (('node__parent', 4, 'title'), 'BooleanField'),
            (('node__parent', 4, 'rank'), 'BooleanField'),
            (('node__parent', 4, 'flags__name'), 'BooleanField'),
            (('node__parent', 4, 'missing'), 'missing'),
            (('node__parent', 4, None), 'field path'),
            (('node__parent', 4, ''), 'field path'),
            (('node__parent', 4, 'reset_inheritance', 1), 'triple'),
            (
                ('node__parent_links__parent', 4, 'parent_links__parent'),
                'BooleanField',
            ),
            (
                (
                    'node__held_parents__parent', 4,
                    'held_parents__reset_inheritance',
                ),
                'parent-table',
            ),
            (('node__parent', 4, 'wide__reset_inheritance'), 'parent-table'),
        )
        for role in ('content', 'delegation', 'sponsor'):
            for along, snippet in cases:
                with self.subTest(role=role, along=along):
                    with self.assertRaises(TrustsConfigurationError) as caught:
                        self._register_role(role, along)
                    self.assertIn(snippet, str(caught.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongResetTest(TransactionTestCase):
    """One tree, every inquiry, and the three places a field can live."""

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        models_ = self._models()
        (
            self.Flag, self.Node, self.Link, self.Policy, self.Sheet,
            self.Grant, self.GroupGrant, self.Delegation,
        ) = models_
        self._table_cm = _tables(*models_)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(self.Sheet, 'change_alongreset')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.nodes = {}
        self.sheets = {}
        self._build_tree()
        self.alice = self.User.objects.create_user('ar-alice', password='x')
        self.bob = self.User.objects.create_user('ar-bob', password='x')
        self.carol = self.User.objects.create_user('ar-carol', password='x')
        self.dave = self.User.objects.create_user('ar-dave', password='x')
        self.gina = self.User.objects.create_user('ar-gina', password='x')
        self.erin = self.User.objects.create_user('ar-erin', password='x')
        self.sponsor = self.User.objects.create_user('ar-sponsor', password='x')
        self.delegate = self.User.objects.create_user('ar-delegate', password='x')
        self.editors = Group.objects.create(name='ar-editors')
        self.editors.user_set.add(self.gina)

    def _models(self):
        class Flag(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_flag'

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            trust = models.ForeignKey(
                'self', null=True, related_name='members',
                on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)
            flags = models.ManyToManyField(Flag, related_name='nodes')
            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_node'

        class Link(models.Model):
            parent = models.ForeignKey(
                Node, related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Node, related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_link'

        class Policy(models.Model):
            node = models.ForeignKey(
                Node, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_policy'

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
                db_table = 'arst_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_grant'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_group_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arst_delegation'

        return (
            Flag, Node, Link, Policy, Sheet, Grant, GroupGrant, Delegation,
        )

    def _build_tree(self):
        # P → A(true) → B2, and A0 → B(true) → C(false) → D(true) → E, plus S.
        p = self._node('P')
        a2 = self._node('A2', parent=p, reset=True)
        self._node('B2', parent=a2)
        a = self._node('A')
        self._node('S', parent=a)
        b = self._node('B', parent=a, reset=True)
        self._node('C', parent=b, reset=False)
        d = self._node('D', parent=self.nodes['C'], reset=True)
        self._node('E', parent=d)
        t0 = self._node('T0')
        t1 = self._node('T1', trust=t0, reset=True)
        self._node('T2', trust=t1)

    def _node(self, title, parent=None, reset=None, trust=None):
        node = self.Node.objects.create(
            title=title, parent=parent, trust=trust, reset_inheritance=reset,
        )
        self.nodes[title] = node
        self.sheets[title] = self.Sheet.objects.create(title=title, node=node)
        return node

    def _grant(self, user, title):
        return self.Grant.objects.create(
            user=user, node=self.nodes[title], permission=self.change,
        )

    def _open(self, name, along, *, delegation_along=_OMIT, group=False):
        handle = compiler(path='tests.core.along-reset.%s' % name)
        if group:
            handle.register(
                trust=self.GroupGrant,
                user='group__user',
                group='group',
                content='node__sheets',
                along=along,
            )
        else:
            handle.register(
                trust=self.Grant,
                user='user',
                permission='permission',
                content='node__sheets',
                along=along,
            )
        if delegation_along is not _OMIT:
            handle.register(
                trust=self.Delegation,
                delegate='delegate',
                sponsor='sponsor',
                content='node__sheets',
                along=delegation_along,
            )
        return handle

    def _assert_user(self, handle, user, titles, *, group=False):
        want = set(titles)
        sheets = list(self.Sheet.objects.all())
        catalog = built_catalog(handle)
        with _listed(handle):
            with self.assertNumQueries(1):
                permitted = set(
                    self.Sheet.objects.permitted(
                        self.code, user,
                    ).values_list('title', flat=True),
                )
            with self.assertNumQueries(1):
                authorized = set(
                    self.Sheet.objects.authorized(
                        user, self.change,
                    ).values_list('title', flat=True),
                )
            for sheet in sheets:
                allowed = sheet.title in want
                self.assertEqual(
                    user.has_perm(self.code, sheet), allowed, sheet.title,
                )
                holders = set(sheet.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                self.assertEqual(user.pk in holders, allowed, sheet.title)
                codes = user.get_all_permissions(sheet)
                self.assertEqual(self.code in codes, allowed, sheet.title)
                if group:
                    grouped = user.get_group_permissions(sheet)
                    self.assertEqual(self.code in grouped, allowed, sheet.title)
        self.assertEqual(permitted, want)
        self.assertEqual(authorized, want)
        listed = scoped_permitted_content(
            self.Node.objects.all(), user, self.change,
            content=self.Sheet, registry=catalog,
        )
        with self.assertNumQueries(1):
            nodes = set(listed.values_list('title', flat=True))
        self.assertEqual(nodes, want)
        allowed_sheet = self.sheets[next(iter(want))] if want else None
        denied = next(sheet for sheet in sheets if sheet.title not in want)
        if allowed_sheet is not None:
            held = catalog.permissions_for(
                user, self.Sheet.objects.filter(pk=allowed_sheet.pk),
            )
            self.assertEqual(set(held.values_list('pk', flat=True)), {self.change.pk})
        self.assertEqual(list(catalog.permissions_for(
            user, self.Sheet.objects.filter(pk=denied.pk),
        )), [])
        if allowed_sheet is not None:
            mixed = self.Sheet.objects.filter(pk__in=(allowed_sheet.pk, denied.pk))
            self.assertEqual(list(catalog.permissions_for(user, mixed)), [])

    def test_node_field_cuts_ancestors_and_keeps_the_stop_grant(self):
        self._grant(self.alice, 'A')
        self._grant(self.bob, 'B')
        self._grant(self.carol, 'C')
        self._grant(self.dave, 'D')
        self._grant(self.erin, 'P')
        self._grant(self.erin, 'A2')
        handle = self._open('node', ('node__parent', 8, 'reset_inheritance'))
        self._assert_user(handle, self.alice, ('A', 'S'))
        self._assert_user(handle, self.bob, ('B', 'C'))
        self._assert_user(handle, self.carol, ('C',))
        self._assert_user(handle, self.dave, ('D', 'E'))
        self._assert_user(handle, self.erin, ('P', 'A2', 'B2'))
        self._grant(self.alice, 'C')
        self._assert_user(handle, self.alice, ('A', 'S', 'C'))

        @authorization_required(self.Sheet, self.code)
        def view(request, pk):
            return 'ok'

        with _listed(handle):
            self.assertEqual(view(_request(self.alice), pk=self.sheets['A'].pk), 'ok')
            with self.assertRaises(PermissionDenied):
                view(_request(self.alice), pk=self.sheets['B'].pk)

    def test_cycle_does_not_carry_an_earlier_grant_through_a_stop(self):
        p = self._node('CP')
        q = self._node('CQ', reset=True)
        r = self._node('CR')
        p.parent = r
        p.save(update_fields=['parent'])
        q.parent = p
        q.save(update_fields=['parent'])
        r.parent = q
        r.save(update_fields=['parent'])
        self._grant(self.alice, 'CP')
        self._grant(self.bob, 'CQ')
        handle = self._open('cycle', ('node__parent', 8, 'reset_inheritance'))
        self._assert_user(handle, self.alice, ('CP',))
        self._assert_user(handle, self.bob, ('CQ', 'CR', 'CP'))

    def test_node_field_cuts_every_link_into_that_node(self):
        self._node('EA')
        self._node('EB', reset=True)
        self._node('EC')
        self.Link.objects.create(parent=self.nodes['EA'], child=self.nodes['EB'])
        self.Link.objects.create(parent=self.nodes['EB'], child=self.nodes['EC'])
        self._grant(self.alice, 'EA')
        self._grant(self.bob, 'EB')
        handle = self._open('edge-node', (
            'node__parent_links__parent', 8, 'reset_inheritance',
        ))
        self._assert_user(handle, self.alice, ('EA',))
        self._assert_user(handle, self.bob, ('EB', 'EC'))

    def test_children_direction_cuts_at_a_true_parent(self):
        self._grant(self.carol, 'C')
        self._grant(self.bob, 'B')
        handle = self._open('shape-c', ('node__children', 8, 'reset_inheritance'))
        self._assert_user(handle, self.carol, ('C',))
        self._assert_user(handle, self.bob, ('B', 'A'))

    def test_trust_field_uses_the_same_cut(self):
        self._grant(self.alice, 'T0')
        self._grant(self.bob, 'T1')
        handle = self._open('trust', ('node__trust', 8, 'reset_inheritance'))
        self._assert_user(handle, self.alice, ('T0',))
        self._assert_user(handle, self.bob, ('T1', 'T2'))

    def test_group_grant_follows_the_node_field(self):
        self.editors.permissions.add(self.change)
        self.GroupGrant.objects.create(group=self.editors, node=self.nodes['A'])
        handle = self._open(
            'group', ('node__parent', 8, 'reset_inheritance'), group=True,
        )
        self._assert_user(handle, self.gina, ('A', 'S'), group=True)

    def test_sponsor_and_delegation_walks_use_their_own_fields(self):
        self._grant(self.sponsor, 'A')
        self.Delegation.objects.create(
            delegate=self.delegate, sponsor=self.sponsor, node=self.nodes['A'],
        )
        sponsor_cut = self._open(
            'sponsor-cut',
            ('node__parent', 8, 'reset_inheritance'),
            delegation_along=('node__parent', 8),
        )
        self._assert_user(sponsor_cut, self.delegate, ('A', 'S'))
        self._assert_user(sponsor_cut, self.sponsor, ('A', 'S'))
        self.Grant.objects.all().delete()
        self._grant(self.sponsor, 'A')
        delegation_cut = self._open(
            'delegation-cut',
            ('node__parent', 8),
            delegation_along=('node__parent', 8, 'reset_inheritance'),
        )
        self._assert_user(delegation_cut, self.sponsor, (
            'A', 'S', 'B', 'C', 'D', 'E',
        ))
        self._assert_user(delegation_cut, self.delegate, ('A', 'S'))

    def test_link_field_cuts_one_edge_and_leaves_the_other(self):
        self.Link.objects.create(
            parent=self.nodes['A'], child=self.nodes['B'], reset_inheritance=True,
        )
        self.Link.objects.create(
            parent=self.nodes['D'], child=self.nodes['B'], reset_inheritance=None,
        )
        self.Link.objects.create(
            parent=self.nodes['B'], child=self.nodes['C'], reset_inheritance=False,
        )
        self._grant(self.alice, 'A')
        self._grant(self.dave, 'D')
        self._grant(self.bob, 'B')
        handle = self._open('link', (
            'node__parent_links__parent', 8, 'parent_links__reset_inheritance',
        ))
        self._assert_user(handle, self.alice, ('A',))
        self._assert_user(handle, self.dave, ('D', 'B', 'C'))
        self._assert_user(handle, self.bob, ('B', 'C'))
        self.Link.objects.create(
            parent=self.nodes['A'], child=self.nodes['B'], reset_inheritance=None,
        )
        self._assert_user(handle, self.alice, ('A', 'B', 'C'))
        left = self._node('LA')
        right = self._node('LB', reset=True)
        self.Link.objects.create(parent=left, child=right, reset_inheritance=None)
        self.Link.objects.create(parent=right, child=left, reset_inheritance=True)
        self._grant(self.carol, 'LA')
        self._grant(self.erin, 'LB')
        self._assert_user(handle, self.carol, ('LA', 'LB'))
        self._assert_user(handle, self.erin, ('LB',))

    def test_related_row_stops_the_node_when_any_value_is_true(self):
        false = self.Flag.objects.create(reset_inheritance=False)
        true = self.Flag.objects.create(reset_inheritance=True)
        empty = self.Flag.objects.create(reset_inheritance=None)
        self.nodes['B'].flags.add(false, true)
        self.nodes['C'].flags.add(empty)
        self._grant(self.alice, 'A')
        self._grant(self.bob, 'B')
        handle = self._open('flags', (
            'node__parent', 8, 'flags__reset_inheritance',
        ))
        self._assert_user(handle, self.alice, ('A', 'S'))
        self._assert_user(handle, self.bob, ('B', 'C', 'D', 'E'))
        self.nodes['D'].flags.add(
            self.Flag.objects.create(reset_inheritance=True),
        )
        self._grant(self.dave, 'C')
        self._assert_user(handle, self.dave, ('C',))
        self._grant(self.erin, 'D')
        self._assert_user(handle, self.erin, ('D', 'E'))

    def test_reverse_fk_stops_the_node_when_any_row_is_true(self):
        self.Policy.objects.create(node=self.nodes['B'], reset_inheritance=False)
        self.Policy.objects.create(node=self.nodes['B'], reset_inheritance=True)
        self.Policy.objects.create(node=self.nodes['C'], reset_inheritance=None)
        self._grant(self.alice, 'A')
        self._grant(self.bob, 'B')
        handle = self._open('policies', (
            'node__parent', 8, 'policies__reset_inheritance',
        ))
        self._assert_user(handle, self.alice, ('A', 'S'))
        self._assert_user(handle, self.bob, ('B', 'C', 'D', 'E'))

    def test_lockfile_records_the_configured_field(self):
        handle = self._open('lock', ('node__parent', 8, 'reset_inheritance'))
        text = render_configured_policy(handle).decode()
        self.assertIn('reset: "reset_inheritance"', text)
        self.assertIn('__reset_reset_inheritance', text)
        self.assertIn('IS NOT TRUE', text)
        self.assertNotIn('NOT EXISTS', text)
        plain = self._open('plain', ('node__parent', 8))
        plain_text = render_configured_policy(plain).decode()
        self.assertNotIn('reset:', plain_text)
        self.assertNotIn('IS NOT TRUE', plain_text)
        flags = self._open('lock-flags', (
            'node__parent', 8, 'flags__reset_inheritance',
        ))
        flags_text = render_configured_policy(flags).decode()
        self.assertIn('reset: "flags__reset_inheritance"', flags_text)
        self.assertIn('NOT EXISTS', flags_text)
        policies = self._open('lock-policies', (
            'node__parent', 8, 'policies__reset_inheritance',
        ))
        policies_text = render_configured_policy(policies).decode()
        self.assertIn('reset: "policies__reset_inheritance"', policies_text)
        self.assertIn('NOT EXISTS', policies_text)
        self.assertIn('"arst_policy"', policies_text)
