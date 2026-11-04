"""``along=(path, bound, field)`` cuts inherited reach at a true field.

``NULL`` and false inherit. A grant on a stop still applies there and
can continue. A content walk, a delegation walk, and a sponsor walk
each honor the field configured on that walk.
"""
from contextlib import contextmanager
from types import SimpleNamespace

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
    forget_models,
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
                        self.assertEqual(
                            reset.far_column,
                            field.remote_field.model._meta.pk.column,
                        )
                    elif name == 'reverse-m2m':
                        forward = self.Node._meta.get_field('marks').field
                        self.assertEqual(
                            reset.through_node, forward.m2m_reverse_name(),
                        )
                        self.assertEqual(reset.far_fk, forward.m2m_column_name())
                        self.assertEqual(
                            reset.far_column, forward.model._meta.pk.column,
                        )
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
        self.assertIn('arst_policy', policies_text)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongResetTargetColumnTest(TransactionTestCase):
    """Non-PK ``to_field`` and ``db_column`` still cut the walk.

    Every foreign key in the tree targets ``code`` and stores that
    value under a column name that is not the attname. Forward
    ``has_perm`` and inverse ``get_permitted_users`` agree.
    """

    def setUp(self):
        super().setUp()
        self.User = get_user_model()
        models_ = self._models()
        (
            self.Flag, self.Mark, self.Node, self.FlagLink, self.MarkLink,
            self.Policy, self.Link, self.Sheet, self.Grant, self.Delegation,
        ) = models_
        self._table_cm = _tables(*models_)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(self.Sheet, 'change_along_reset_field')
        self.perm = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.sponsor = self.User.objects.create_user('arf-sponsor', password='x')
        self.delegate = self.User.objects.create_user('arf-delegate', password='x')
        self.bob = self.User.objects.create_user('arf-bob', password='x')
        self.nodes = {}
        self.sheets = {}
        parent = None
        for code, stopped in (('A', None), ('B', True), ('C', False)):
            node = self.Node.objects.create(
                code=code, parent=parent, reset_inheritance=stopped,
            )
            parent = node
            self.nodes[code] = node
            self.sheets[code] = self.Sheet.objects.create(title=code, node=node)
        self.Link.objects.create(
            parent=self.nodes['A'], child=self.nodes['B'], reset_inheritance=True,
        )
        self.Link.objects.create(
            parent=self.nodes['B'], child=self.nodes['C'], reset_inheritance=False,
        )
        kept = self.Flag.objects.create(code='keep', reset_inheritance=False)
        stopped = self.Flag.objects.create(code='stop', reset_inheritance=True)
        self.nodes['B'].flags.add(kept, stopped)
        mark = self.Mark.objects.create(code='stop', reset_inheritance=True)
        mark.nodes.add(self.nodes['B'])
        self.Policy.objects.create(node=self.nodes['B'], reset_inheritance=False)
        self.Policy.objects.create(node=self.nodes['B'], reset_inheritance=True)

    def _models(self):
        class Flag(models.Model):
            code = models.CharField(max_length=20, unique=True, db_column='flag_key')
            reset_inheritance = models.BooleanField(null=True, db_column='flag_stop')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_flag'

        class Mark(models.Model):
            code = models.CharField(max_length=20, unique=True, db_column='mark_key')
            reset_inheritance = models.BooleanField(null=True, db_column='mark_stop')
            nodes = models.ManyToManyField(
                'Node', through='MarkLink', through_fields=('mark', 'node'),
                related_name='marks',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_mark'

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            code = models.CharField(max_length=20, unique=True, db_column='node_key')
            parent = models.ForeignKey(
                'self', to_field='code', db_column='parent_key', null=True,
                related_name='children', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True, db_column='stop_flag')
            flags = models.ManyToManyField(
                Flag, through='FlagLink', through_fields=('node', 'flag'),
                related_name='nodes',
            )
            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_node'

        class FlagLink(models.Model):
            node = models.ForeignKey(
                Node, to_field='code', db_column='from_node',
                related_name='flag_links', on_delete=models.CASCADE,
            )
            flag = models.ForeignKey(
                Flag, to_field='code', db_column='to_flag',
                related_name='node_links', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_flag_link'

        class MarkLink(models.Model):
            mark = models.ForeignKey(
                Mark, to_field='code', db_column='to_mark',
                related_name='node_links', on_delete=models.CASCADE,
            )
            node = models.ForeignKey(
                Node, to_field='code', db_column='mark_node',
                related_name='mark_links', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_mark_link'

        class Policy(models.Model):
            node = models.ForeignKey(
                Node, to_field='code', db_column='policy_node',
                related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True, db_column='policy_stop')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_policy'

        class Link(models.Model):
            parent = models.ForeignKey(
                Node, to_field='code', db_column='edge_parent',
                related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Node, to_field='code', db_column='edge_child',
                related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True, db_column='link_stop')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_link'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            node = models.ForeignKey(
                Node, to_field='code', db_column='sheet_node',
                related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(
                Node, to_field='code', db_column='grant_node',
                on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_grant'

        class Delegation(models.Model):
            delegate = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(
                Node, to_field='code', db_column='deleg_node',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arf_delegation'

        return (
            Flag, Mark, Node, FlagLink, MarkLink, Policy, Link, Sheet,
            Grant, Delegation,
        )

    def _register(self, name, along, delegation_along=None):
        handle = compiler(path='tests.core.along-reset-field.%s' % name)
        record = handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='node__sheets',
            along=along,
        )
        if delegation_along is not None:
            handle.register(
                trust=self.Delegation,
                delegate='delegate',
                sponsor='sponsor',
                content='node__sheets',
                along=delegation_along,
            )
        return handle, record

    def test_resolved_columns_follow_the_foreign_key_target(self):
        cases = (
            ('node', ('node__parent', 8, 'reset_inheritance'), {
                'kind': 'node', 'column': 'stop_flag',
            }),
            ('children', ('node__children', 8, 'reset_inheritance'), {
                'kind': 'node', 'column': 'stop_flag',
            }),
            ('edge', (
                'node__parent_links__parent', 8, 'parent_links__reset_inheritance',
            ), {
                'kind': 'edge', 'column': 'link_stop',
            }),
            ('m2m', ('node__parent', 8, 'flags__reset_inheritance'), {
                'kind': 'any', 'column': 'flag_stop',
                'node_column': 'node_key', 'through_node': 'from_node',
                'far_column': 'flag_key', 'far_fk': 'to_flag',
            }),
            ('reverse-m2m', ('node__parent', 8, 'marks__reset_inheritance'), {
                'kind': 'any', 'column': 'mark_stop',
                'node_column': 'node_key', 'through_node': 'mark_node',
                'far_column': 'mark_key', 'far_fk': 'to_mark',
            }),
            ('reverse-fk', ('node__parent', 8, 'policies__reset_inheritance'), {
                'kind': 'any', 'column': 'policy_stop',
                'node_column': 'node_key', 'through_node': 'policy_node',
                'far_table': None,
            }),
        )
        for name, along, expect in cases:
            with self.subTest(placement=name):
                handle, record = self._register(name, along)
                reset = record.along.reset
                for key, value in expect.items():
                    self.assertEqual(getattr(reset, key), value, key)
                if name == 'm2m':
                    self.assertNotEqual(
                        reset.far_column, self.Flag._meta.pk.column,
                    )
                    text = render_configured_policy(handle).decode()
                    self.assertIn('flag_key', text)
                    self.assertIn('from_node', text)
                    self.assertIn('to_flag', text)
                    self.assertIn('flag_stop', text)
                    self.assertIn('node_key', text)
                    self.assertIn('parent_key', text)
                if name == 'node':
                    text = render_configured_policy(handle).decode()
                    self.assertIn('stop_flag', text)
                    self.assertIn('node_key', text)
                    self.assertIn('parent_key', text)
                    self.assertIn('grant_node', text)

    def test_non_pk_target_cuts_forward_and_inverse(self):
        placements = (
            ('node', ('node__parent', 8, 'reset_inheritance'), 'down'),
            ('children', ('node__children', 8, 'reset_inheritance'), 'up'),
            ('edge', (
                'node__parent_links__parent', 8,
                'parent_links__reset_inheritance',
            ), 'down'),
            ('m2m', ('node__parent', 8, 'flags__reset_inheritance'), 'down'),
            ('reverse-m2m', ('node__parent', 8, 'marks__reset_inheritance'), 'down'),
            ('reverse-fk', ('node__parent', 8, 'policies__reset_inheritance'), 'down'),
        )
        users = {
            'sponsor': self.sponsor,
            'delegate': self.delegate,
            'bob': self.bob,
        }
        for role in ('content', 'delegation', 'sponsor'):
            for name, along, direction in placements:
                with self.subTest(role=role, placement=name):
                    self.Grant.objects.all().delete()
                    self.Delegation.objects.all().delete()
                    start = 'A' if direction == 'down' else 'C'
                    self.Grant.objects.create(
                        user=self.sponsor, node=self.nodes[start],
                        permission=self.change,
                    )
                    self.Grant.objects.create(
                        user=self.bob, node=self.nodes['B'],
                        permission=self.change,
                    )
                    plain = along[:2]
                    if role == 'content':
                        handle, _record = self._register(
                            '%s-%s' % (role, name), along,
                        )
                    elif role == 'delegation':
                        handle, _record = self._register(
                            '%s-%s' % (role, name), plain,
                            delegation_along=along,
                        )
                        self.Delegation.objects.create(
                            delegate=self.delegate, sponsor=self.sponsor,
                            node=self.nodes[start],
                        )
                    else:
                        handle, _record = self._register(
                            '%s-%s' % (role, name), along,
                            delegation_along=plain,
                        )
                        self.Delegation.objects.create(
                            delegate=self.delegate, sponsor=self.sponsor,
                            node=self.nodes[start],
                        )
                    if direction == 'down':
                        start_set, own = {'A'}, {'B', 'C'}
                        plain_set = {'A', 'B', 'C'}
                    else:
                        start_set, own = {'C'}, {'B', 'A'}
                        plain_set = {'A', 'B', 'C'}
                    if role == 'delegation':
                        expect = {
                            'sponsor': plain_set,
                            'delegate': start_set,
                            'bob': own,
                        }
                    elif role == 'sponsor':
                        expect = {
                            'sponsor': start_set,
                            'delegate': start_set,
                            'bob': own,
                        }
                    else:
                        expect = {'sponsor': start_set, 'bob': own}
                    with _listed(handle):
                        for label, want in expect.items():
                            got = self._reached(users[label])
                            self.assertEqual(got, want, label)

    def _reached(self, user):
        forward = set()
        inverse = set()
        for code, sheet in self.sheets.items():
            if user.has_perm(self.perm, sheet):
                forward.add(code)
            holders = sheet.get_permitted_users(self.change)
            if user.pk in set(holders.values_list('pk', flat=True)):
                inverse.add(code)
        self.assertEqual(forward, inverse)
        return forward


def _meta(table):
    return type('Meta', (), {
        'app_label': 'trusts_tests',
        'db_table': table,
    })


def _new(name, table, bases, **fields):
    fields['__module__'] = __name__
    fields['Meta'] = _meta(table)
    return type(name, bases, fields)


def _fk(target, related, *, null=False, to_field=None, column=None):
    opts = {'on_delete': models.CASCADE, 'related_name': related}
    if null:
        opts['null'] = True
    if to_field:
        opts['to_field'] = to_field
    if column:
        opts['db_column'] = column
    return models.ForeignKey(target, **opts)


_COLUMN_CASES = (
    ('Tfn', 'node', 'to_field'),
    ('Dcn', 'node', 'db_column'),
    ('Tfl', 'link', 'to_field'),
    ('Dcl', 'link', 'db_column'),
    ('Tfs', 'm2m-node', 'to_field'),
    ('Dcs', 'm2m-node', 'db_column'),
    ('Tff', 'm2m-far', 'to_field'),
    ('Dcf', 'm2m-far', 'db_column'),
    ('Tfr', 'reverse-fk', 'to_field'),
    ('Dcr', 'reverse-fk', 'db_column'),
)


def _site_placements(site):
    if site == 'node':
        return (
            ('node', ('node__parent', 8, 'reset_inheritance'), 'down'),
            ('children', ('node__children', 8, 'reset_inheritance'), 'up'),
        )
    if site == 'link':
        return (
            ('edge', (
                'node__parent_links__parent', 8,
                'parent_links__reset_inheritance',
            ), 'down'),
        )
    if site in ('m2m-node', 'm2m-far'):
        return (
            ('m2m', ('node__parent', 8, 'flags__reset_inheritance'), 'down'),
            ('reverse-m2m', (
                'node__parent', 8, 'marks__reset_inheritance',
            ), 'down'),
        )
    return (
        ('reverse-fk', (
            'node__parent', 8, 'policies__reset_inheritance',
        ), 'down'),
    )


def _reach_expect(direction, role):
    if direction == 'down':
        start, own, plain = {'A'}, {'B', 'C'}, {'A', 'B', 'C'}
    else:
        start, own, plain = {'C'}, {'B', 'A'}, {'A', 'B', 'C'}
    if role == 'delegation':
        return {'sponsor': plain, 'delegate': start, 'bob': own}
    if role == 'sponsor':
        return {'sponsor': start, 'delegate': start, 'bob': own}
    return {'sponsor': start, 'bob': own}


def _role_alongs(along, role):
    plain = along[:2]
    if role == 'delegation':
        return plain, along
    if role == 'sponsor':
        return along, plain
    return along, None


def _open_reset(name, grant_model, delegation_model, along, delegation_along=None):
    handle = compiler(path='tests.core.along-reset-cat.%s' % name)
    content = handle.register(
        trust=grant_model,
        user='user',
        permission='permission',
        content='node__sheets',
        along=along,
    )
    deleg = None
    if delegation_along is not None:
        deleg = handle.register(
            trust=delegation_model,
            delegate='delegate',
            sponsor='sponsor',
            content='node__sheets',
            along=delegation_along,
        )
    return handle, content, deleg


def _sql_fragments(site, quirk, placement):
    if site == 'node' and quirk == 'to_field':
        return ('code', 'parent_id')
    if site == 'node':
        return ('parent_key',)
    if site == 'link' and quirk == 'to_field':
        return ('code', 'parent_id', 'child_id')
    if site == 'link':
        return ('edge_parent', 'edge_child')
    if quirk == 'to_field':
        return ('code',)
    if site == 'm2m-node' and placement == 'm2m':
        return ('from_node',)
    if site == 'm2m-node':
        return ('mark_node',)
    if site == 'm2m-far' and placement == 'm2m':
        return ('to_flag',)
    if site == 'm2m-far':
        return ('to_mark',)
    return ('policy_node',)


def _column_models(tag, site, quirk):
    """One schema. Only ``site`` carries ``quirk``; every other FK is plain."""
    prefix = 'ari_%s_' % tag.lower()
    user = get_user_model()
    to_field = quirk == 'to_field'
    renamed = quirk == 'db_column'
    ident_code = to_field and site in ('node', 'link')
    node_code = to_field and site in ('node', 'link', 'm2m-node', 'reverse-fk')
    far_code = to_field and site == 'm2m-far'
    has_parent = site != 'link'
    has_m2m = site in ('m2m-node', 'm2m-far')
    grant_opts = {'to_field': 'code'} if ident_code else {}

    def renamed_column(name, active):
        return name if active else None

    flag = flag_link = mark = mark_link = link = policy = None
    if has_m2m:
        flag_fields = {'reset_inheritance': models.BooleanField(null=True)}
        if far_code:
            flag_fields['code'] = models.CharField(max_length=20, unique=True)
        flag = _new(
            'Flag%s' % tag, prefix + 'flag', (models.Model,), **flag_fields,
        )
    node_fields = {}
    if node_code:
        node_fields['code'] = models.CharField(max_length=20, unique=True)
    if has_parent:
        node_fields['parent'] = _fk(
            'self', 'children', null=True,
            to_field='code' if to_field and site == 'node' else None,
            column=renamed_column('parent_key', renamed and site == 'node'),
        )
    if site == 'node':
        node_fields['reset_inheritance'] = models.BooleanField(null=True)
    if has_m2m:
        node_fields['flags'] = models.ManyToManyField(
            flag,
            through='trusts_tests.FlagLink%s' % tag,
            through_fields=('node', 'flag'),
            related_name='nodes',
        )
    node = _new('Node%s' % tag, prefix + 'node', (models.Model,), **node_fields)
    if has_m2m:
        flag_link = _new(
            'FlagLink%s' % tag, prefix + 'flink', (models.Model,),
            node=_fk(
                node, '+',
                to_field='code' if to_field and site == 'm2m-node' else None,
                column=renamed_column(
                    'from_node', renamed and site == 'm2m-node',
                ),
            ),
            flag=_fk(
                flag, '+',
                to_field='code' if far_code else None,
                column=renamed_column('to_flag', renamed and site == 'm2m-far'),
            ),
        )
        mark_fields = {'reset_inheritance': models.BooleanField(null=True)}
        if far_code:
            mark_fields['code'] = models.CharField(max_length=20, unique=True)
        mark_fields['nodes'] = models.ManyToManyField(
            node,
            through='trusts_tests.MarkLink%s' % tag,
            through_fields=('mark', 'node'),
            related_name='marks',
        )
        mark = _new(
            'Mark%s' % tag, prefix + 'mark', (models.Model,), **mark_fields,
        )
        mark_link = _new(
            'MarkLink%s' % tag, prefix + 'mlink', (models.Model,),
            mark=_fk(
                mark, '+',
                to_field='code' if far_code else None,
                column=renamed_column('to_mark', renamed and site == 'm2m-far'),
            ),
            node=_fk(
                node, '+',
                to_field='code' if to_field and site == 'm2m-node' else None,
                column=renamed_column(
                    'mark_node', renamed and site == 'm2m-node',
                ),
            ),
        )
    if site == 'link':
        link_to = 'code' if to_field else None
        link = _new(
            'Link%s' % tag, prefix + 'link', (models.Model,),
            parent=_fk(
                node, 'child_links', to_field=link_to,
                column=renamed_column('edge_parent', renamed),
            ),
            child=_fk(
                node, 'parent_links', to_field=link_to,
                column=renamed_column('edge_child', renamed),
            ),
            reset_inheritance=models.BooleanField(null=True),
        )
    if site == 'reverse-fk':
        policy = _new(
            'Policy%s' % tag, prefix + 'policy', (models.Model,),
            node=_fk(
                node, 'policies',
                to_field='code' if to_field else None,
                column=renamed_column('policy_node', renamed),
            ),
            reset_inheritance=models.BooleanField(null=True),
        )
    sheet_qs = type(
        'SheetQs%s' % tag,
        (PermittedQuerySetMixin, AuthorizedQuerySet),
        {'__module__': __name__},
    )
    sheet = _new(
        'Sheet%s' % tag, prefix + 'sheet',
        (PermittedUsersMixin, models.Model),
        title=models.CharField(max_length=20),
        node=_fk(node, 'sheets', **grant_opts),
        objects=models.Manager.from_queryset(sheet_qs)(),
    )
    grant = _new(
        'Grant%s' % tag, prefix + 'grant', (models.Model,),
        user=_fk(user, '+'),
        node=_fk(node, '+', **grant_opts),
        permission=_fk(Permission, '+'),
    )
    delegation = _new(
        'Delegation%s' % tag, prefix + 'deleg', (models.Model,),
        delegate=_fk(user, '+'),
        sponsor=_fk(user, '+'),
        node=_fk(node, '+', **grant_opts),
    )
    models_ = tuple(item for item in (
        flag, node, flag_link, mark, mark_link, link, policy,
        sheet, grant, delegation,
    ) if item is not None)
    return SimpleNamespace(
        tag=tag, site=site, quirk=quirk, models=models_,
        node_code=node_code, far_code=far_code, has_parent=has_parent,
        Flag=flag, Node=node, FlagLink=flag_link, Mark=mark,
        MarkLink=mark_link, Link=link, Policy=policy, Sheet=sheet,
        Grant=grant, Delegation=delegation,
    )


def _populate_column(built):
    built.nodes = {}
    built.sheets = {}
    parent = None
    for label in ('A', 'B', 'C'):
        kwargs = {}
        if built.node_code:
            kwargs['code'] = label
        if built.has_parent:
            kwargs['parent'] = parent
        node = built.Node.objects.create(**kwargs)
        parent = node
        built.nodes[label] = node
        built.sheets[label] = built.Sheet.objects.create(title=label, node=node)
    if built.site == 'node':
        built.nodes['B'].reset_inheritance = True
        built.nodes['B'].save(update_fields=['reset_inheritance'])
        built.nodes['C'].reset_inheritance = False
        built.nodes['C'].save(update_fields=['reset_inheritance'])
        return
    if built.site == 'link':
        built.Link.objects.create(
            parent=built.nodes['A'], child=built.nodes['B'],
            reset_inheritance=True,
        )
        built.Link.objects.create(
            parent=built.nodes['B'], child=built.nodes['C'],
            reset_inheritance=False,
        )
        return
    if built.site in ('m2m-node', 'm2m-far'):
        def flagged(model, value, code):
            kwargs = {'reset_inheritance': value}
            if built.far_code:
                kwargs['code'] = code
            return model.objects.create(**kwargs)

        kept = flagged(built.Flag, False, 'keep')
        stopped = flagged(built.Flag, True, 'stop')
        built.FlagLink.objects.create(node=built.nodes['B'], flag=kept)
        built.FlagLink.objects.create(node=built.nodes['B'], flag=stopped)
        built.MarkLink.objects.create(
            mark=flagged(built.Mark, False, 'keep'), node=built.nodes['B'],
        )
        built.MarkLink.objects.create(
            mark=flagged(built.Mark, True, 'stop'), node=built.nodes['B'],
        )
        return
    built.Policy.objects.create(
        node=built.nodes['B'], reset_inheritance=False,
    )
    built.Policy.objects.create(
        node=built.nodes['B'], reset_inheritance=True,
    )


def _forward_and_inverse(sheets, perm, change, user):
    forward = set()
    inverse = set()
    for title, sheet in sheets.items():
        if user.has_perm(perm, sheet):
            forward.add(title)
        holders = sheet.get_permitted_users(change)
        if user.pk in set(holders.values_list('pk', flat=True)):
            inverse.add(title)
    return forward, inverse


def _inquiry_sets(sheet_model, node_model, sheets, perm, change, catalog, user):
    """The six inquiries, each as the set of sheet titles it allows."""

    @authorization_required(sheet_model, perm)
    def view(request, pk):
        return 'ok'

    permitted = set(
        sheet_model.objects.permitted(perm, user).values_list('title', flat=True),
    )
    has_perm = set()
    holders = set()
    views = set()
    common = set()
    for title, sheet in sheets.items():
        if user.has_perm(perm, sheet):
            has_perm.add(title)
        found = sheet.get_permitted_users(change)
        if user.pk in set(found.values_list('pk', flat=True)):
            holders.add(title)
        try:
            view(_request(user), pk=sheet.pk)
        except PermissionDenied:
            pass
        else:
            views.add(title)
        held = catalog.permissions_for(
            user, sheet_model.objects.filter(pk=sheet.pk),
        )
        if change.pk in set(held.values_list('pk', flat=True)):
            common.add(title)
    listed = scoped_permitted_content(
        node_model.objects.all(), user, change,
        content=sheet_model, registry=catalog,
    )
    filtered = set(listed.values_list('title', flat=True))
    return {
        'permitted': permitted,
        'has_perm': has_perm,
        'get_permitted_users': holders,
        'filter_by_permitted_content': filtered,
        'common_permissions': common,
        'authorization_required': views,
    }


_PLAIN_PLACEMENTS = (
    ('node', ('node__parent', 8, 'reset_inheritance'), 'down'),
    ('children', ('node__children', 8, 'reset_inheritance'), 'up'),
    ('edge', (
        'node__parent_links__parent', 8, 'parent_links__reset_inheritance',
    ), 'down'),
    ('m2m', ('node__parent', 8, 'flags__reset_inheritance'), 'down'),
    ('reverse-m2m', ('node__parent', 8, 'marks__reset_inheritance'), 'down'),
    ('reverse-fk', ('node__parent', 8, 'policies__reset_inheritance'), 'down'),
)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongResetColumnIdentityTest(TransactionTestCase):
    """Column identity, one quirk on one relation at a time.

    ``to_field`` and ``db_column`` are separate. Each is applied to the
    node self-FK, the link row, the through FK that points at the node,
    the far through FK, and the reverse FK. Content, delegation, and
    sponsor walks each have to cut on that relation.
    """

    def setUp(self):
        super().setUp()
        user = get_user_model()
        self.sponsor = user.objects.create_user('arc-sponsor', password='x')
        self.delegate = user.objects.create_user('arc-delegate', password='x')
        self.bob = user.objects.create_user('arc-bob', password='x')
        self.users = {
            'sponsor': self.sponsor,
            'delegate': self.delegate,
            'bob': self.bob,
        }

    def test_to_field_and_db_column_on_each_reset_relation(self):
        for tag, site, quirk in _COLUMN_CASES:
            built = _column_models(tag, site, quirk)
            try:
                with _tables(*built.models):
                    _populate_column(built)
                    built.change = _permission(built.Sheet, 'change_along_reset_cat')
                    built.perm = '%s.%s' % (
                        built.change.content_type.app_label,
                        built.change.codename,
                    )
                    self._exercise(built)
            finally:
                forget_models(*built.models)

    def _exercise(self, built):
        for name, along, direction in _site_placements(built.site):
            for role in ('content', 'delegation', 'sponsor'):
                with self.subTest(
                    site=built.site, quirk=built.quirk,
                    placement=name, role=role,
                ):
                    self._assert_cut(built, name, along, direction, role)

    def _assert_cut(self, built, name, along, direction, role):
        built.Grant.objects.all().delete()
        built.Delegation.objects.all().delete()
        start = 'A' if direction == 'down' else 'C'
        built.Grant.objects.create(
            user=self.sponsor, node=built.nodes[start], permission=built.change,
        )
        built.Grant.objects.create(
            user=self.bob, node=built.nodes['B'], permission=built.change,
        )
        content_along, deleg_along = _role_alongs(along, role)
        if role != 'content':
            built.Delegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor,
                node=built.nodes[start],
            )
        handle, content, deleg = _open_reset(
            '%s-%s-%s' % (built.tag, role, name),
            built.Grant, built.Delegation, content_along, deleg_along,
        )
        record = deleg if role == 'delegation' else content
        self._assert_resolved(built, name, record)
        if role == 'content':
            text = render_configured_policy(handle).decode()
            for fragment in _sql_fragments(built.site, built.quirk, name):
                self.assertIn(fragment, text)
        expect = _reach_expect(direction, role)
        with _listed(handle):
            for label, want in expect.items():
                forward, inverse = _forward_and_inverse(
                    built.sheets, built.perm, built.change, self.users[label],
                )
                self.assertEqual(forward, inverse, label)
                self.assertEqual(forward, want, label)

    def _assert_resolved(self, built, placement, record):
        reset = record.along.reset
        walk = record.along
        site, quirk = built.site, built.quirk
        pk = built.Node._meta.pk
        if site in ('node', 'link') and quirk == 'to_field':
            self.assertEqual(walk.walk_ident, 'code')
        else:
            self.assertEqual(walk.walk_ident, pk.attname)
        if site == 'node':
            parent = built.Node._meta.get_field('parent')
            self.assertEqual(reset.kind, 'node')
            self.assertEqual(reset.column, 'reset_inheritance')
            self.assertEqual(walk.parent_attname, 'parent_id')
            if quirk == 'to_field':
                self.assertEqual(parent.column, 'parent_id')
                self.assertEqual(parent.target_field.column, 'code')
                self.assertIsNot(parent.target_field, pk)
            else:
                self.assertEqual(parent.column, 'parent_key')
                self.assertEqual(parent.attname, 'parent_id')
                self.assertEqual(parent.target_field, pk)
            return
        if site == 'link':
            parent = built.Link._meta.get_field('parent')
            child = built.Link._meta.get_field('child')
            self.assertEqual(reset.kind, 'edge')
            self.assertEqual(reset.column, 'reset_inheritance')
            self.assertEqual(walk.edge_parent_attname, 'parent_id')
            self.assertEqual(walk.edge_child_attname, 'child_id')
            if quirk == 'to_field':
                self.assertEqual(parent.target_field.column, 'code')
                self.assertEqual(child.target_field.column, 'code')
                self.assertEqual(parent.column, 'parent_id')
                self.assertEqual(child.column, 'child_id')
                self.assertIsNot(parent.target_field, pk)
            else:
                self.assertEqual(parent.column, 'edge_parent')
                self.assertEqual(child.column, 'edge_child')
                self.assertEqual(parent.target_field, pk)
                self.assertEqual(child.target_field, pk)
            return
        if site == 'reverse-fk':
            fk = built.Policy._meta.get_field('node')
            self.assertEqual(reset.kind, 'any')
            self.assertIsNone(reset.far_table)
            self.assertEqual(reset.column, 'reset_inheritance')
            self.assertEqual(reset.through_node, fk.column)
            self.assertEqual(reset.node_column, fk.target_field.column)
            if quirk == 'to_field':
                self.assertEqual(fk.column, 'node_id')
                self.assertEqual(fk.target_field.column, 'code')
                self.assertIsNot(fk.target_field, pk)
            else:
                self.assertEqual(fk.column, 'policy_node')
                self.assertNotEqual(fk.column, fk.attname)
                self.assertEqual(fk.target_field, pk)
            return
        self.assertEqual(reset.kind, 'any')
        self.assertEqual(reset.column, 'reset_inheritance')
        if placement == 'm2m':
            through, far_model = built.FlagLink, built.Flag
            source_name, far_name = 'node', 'flag'
            if quirk == 'db_column' and site == 'm2m-node':
                source_column, far_column_name = 'from_node', 'flag_id'
            elif quirk == 'db_column':
                source_column, far_column_name = 'node_id', 'to_flag'
            else:
                source_column, far_column_name = 'node_id', 'flag_id'
        else:
            through, far_model = built.MarkLink, built.Mark
            source_name, far_name = 'node', 'mark'
            if quirk == 'db_column' and site == 'm2m-node':
                source_column, far_column_name = 'mark_node', 'mark_id'
            elif quirk == 'db_column':
                source_column, far_column_name = 'node_id', 'to_mark'
            else:
                source_column, far_column_name = 'node_id', 'mark_id'
        source = through._meta.get_field(source_name)
        far = through._meta.get_field(far_name)
        self.assertEqual(source.column, source_column)
        self.assertEqual(far.column, far_column_name)
        self.assertEqual(reset.through_node, source.column)
        self.assertEqual(reset.far_fk, far.column)
        self.assertEqual(reset.node_column, source.target_field.column)
        self.assertEqual(reset.far_column, far.target_field.column)
        if site == 'm2m-node' and quirk == 'to_field':
            self.assertEqual(source.target_field.column, 'code')
            self.assertIsNot(source.target_field, pk)
            self.assertEqual(far.target_field, far_model._meta.pk)
        elif site == 'm2m-far' and quirk == 'to_field':
            self.assertEqual(far.target_field.column, 'code')
            self.assertIsNot(far.target_field, far_model._meta.pk)
            self.assertEqual(source.target_field, pk)
        elif quirk == 'db_column' and site == 'm2m-node':
            self.assertNotEqual(source.column, source.attname)
            self.assertEqual(source.target_field, pk)
            self.assertEqual(far.target_field, far_model._meta.pk)
        else:
            self.assertNotEqual(far.column, far.attname)
            self.assertEqual(far.target_field, far_model._meta.pk)
            self.assertEqual(source.target_field, pk)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongResetInquiryAndNullTest(TransactionTestCase):
    """Inquiry parity and NULL handling on one plain tree.

    A is the root, B the boundary, C the child. Links A→B and B→C
    exist. Flags, marks, and policies are added by the case under test.
    """

    def setUp(self):
        super().setUp()
        user_model = get_user_model()
        models_ = self._models()
        (
            self.Flag, self.Node, self.Mark, self.Link, self.Policy,
            self.Sheet, self.Grant, self.Delegation,
        ) = models_
        self._table_cm = _tables(*models_)
        self._table_cm.__enter__()
        self.addCleanup(self._table_cm.__exit__, None, None, None)
        self.change = _permission(self.Sheet, 'change_along_reset_matrix')
        self.perm = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.nodes = {}
        self.sheets = {}
        parent = None
        for title in ('A', 'B', 'C'):
            node = self.Node.objects.create(title=title, parent=parent)
            parent = node
            self.nodes[title] = node
            self.sheets[title] = self.Sheet.objects.create(title=title, node=node)
        self.Link.objects.create(parent=self.nodes['A'], child=self.nodes['B'])
        self.Link.objects.create(parent=self.nodes['B'], child=self.nodes['C'])
        self.sponsor = user_model.objects.create_user('arm-sponsor', password='x')
        self.delegate = user_model.objects.create_user('arm-delegate', password='x')
        self.bob = user_model.objects.create_user('arm-bob', password='x')
        self.users = {
            'sponsor': self.sponsor,
            'delegate': self.delegate,
            'bob': self.bob,
        }

    def _models(self):
        class Flag(models.Model):
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arm_flag'

        class NodeQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Node(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)
            flags = models.ManyToManyField(Flag, related_name='nodes')
            objects = models.Manager.from_queryset(NodeQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arm_node'

        class Mark(models.Model):
            reset_inheritance = models.BooleanField(null=True)
            nodes = models.ManyToManyField(Node, related_name='marks')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arm_mark'

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
                db_table = 'arm_link'

        class Policy(models.Model):
            node = models.ForeignKey(
                Node, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arm_policy'

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
                db_table = 'arm_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'arm_grant'

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
                db_table = 'arm_delegation'

        return Flag, Node, Mark, Link, Policy, Sheet, Grant, Delegation

    def _clear(self):
        self.Node.objects.update(reset_inheritance=None)
        self.Link.objects.update(reset_inheritance=None)
        self.Flag.objects.all().delete()
        self.Mark.objects.all().delete()
        self.Policy.objects.all().delete()
        self.Grant.objects.all().delete()
        self.Delegation.objects.all().delete()

    def _arm(self, placement, state):
        if state == 'missing':
            return
        if placement in ('node', 'children'):
            node = self.nodes['B']
            node.reset_inheritance = state
            node.save(update_fields=['reset_inheritance'])
            return
        if placement == 'edge':
            link = self.Link.objects.get(
                parent=self.nodes['A'], child=self.nodes['B'],
            )
            link.reset_inheritance = state
            link.save(update_fields=['reset_inheritance'])
            return
        if placement == 'm2m':
            self.nodes['B'].flags.add(
                self.Flag.objects.create(reset_inheritance=state),
            )
            return
        if placement == 'reverse-m2m':
            mark = self.Mark.objects.create(reset_inheritance=state)
            mark.nodes.add(self.nodes['B'])
            return
        self.Policy.objects.create(node=self.nodes['B'], reset_inheritance=state)

    def _grant(self, direction, role):
        start = 'A' if direction == 'down' else 'C'
        self.Grant.objects.create(
            user=self.sponsor, node=self.nodes[start], permission=self.change,
        )
        self.Grant.objects.create(
            user=self.bob, node=self.nodes['B'], permission=self.change,
        )
        if role != 'content':
            self.Delegation.objects.create(
                delegate=self.delegate, sponsor=self.sponsor,
                node=self.nodes[start],
            )
        return start

    def test_inquiries_agree_on_each_placement(self):
        for name, along, direction in _PLAIN_PLACEMENTS:
            for role in ('content', 'delegation', 'sponsor'):
                with self.subTest(placement=name, role=role):
                    self._clear()
                    self._arm(name, True)
                    self._grant(direction, role)
                    content_along, deleg_along = _role_alongs(along, role)
                    handle, _content, _deleg = _open_reset(
                        'parity-%s-%s' % (role, name),
                        self.Grant, self.Delegation, content_along, deleg_along,
                    )
                    catalog = built_catalog(handle)
                    expect = _reach_expect(direction, role)
                    with _listed(handle):
                        for label, want in expect.items():
                            found = _inquiry_sets(
                                self.Sheet, self.Node, self.sheets, self.perm,
                                self.change, catalog, self.users[label],
                            )
                            for inquiry, got in found.items():
                                self.assertEqual(
                                    got, want, '%s %s' % (label, inquiry),
                                )

    def test_null_false_true_and_missing_related_row(self):
        for name, along, direction in _PLAIN_PLACEMENTS:
            states = [None, False, True]
            if name in ('m2m', 'reverse-m2m', 'reverse-fk'):
                states.append('missing')
            for state in states:
                with self.subTest(placement=name, state=state):
                    self._clear()
                    self._arm(name, state)
                    self._grant(direction, 'content')
                    handle, _content, _deleg = _open_reset(
                        'null-%s-%s' % (name, state),
                        self.Grant, self.Delegation, along,
                    )
                    inherit = state is None or state is False or state == 'missing'
                    if direction == 'down':
                        sponsor = {'A', 'B', 'C'} if inherit else {'A'}
                        bob = {'B', 'C'}
                    else:
                        sponsor = {'A', 'B', 'C'} if inherit else {'C'}
                        bob = {'B', 'A'}
                    with _listed(handle):
                        for user, want in (
                            (self.sponsor, sponsor), (self.bob, bob),
                        ):
                            forward, inverse = _forward_and_inverse(
                                self.sheets, self.perm, self.change, user,
                            )
                            self.assertEqual(forward, inverse, user.username)
                            self.assertEqual(forward, want, user.username)
