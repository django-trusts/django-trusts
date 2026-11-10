"""Register checks, condition agreement, and fail-closed inquiries.

These cases exercise paths the kernel suite did not reach: rejected
``register()`` shapes, named filters on permission and user fields,
reverse-inquiry agreement, a catalog-less backend, and bind-once when
the query shape is not one this pass rewrites.
"""

import os
import stat
import tempfile
from pathlib import Path

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import F, Q, Value
from django.db.models.functions import Coalesce as SqlCoalesce, Concat, Lower as SqlLower
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.kernel_host.backends import HostTrustModelBackend
from tests.support import (
    built_catalog,
    compiler,
    published_class_catalog,
    render_configured_policy,
)
from trusts.backends import Recorder, TrustModelBackendMixin
from trusts.compile.compilers import RegistrationListener
from trusts.compile.graph import Along, Ref
from trusts.functions import Coalesce, Lower
from trusts.plan.grammar import Tree
from trusts.decorators import filter_by_permitted_content
from trusts.errors import (
    PermissionConditionError,
    TrustsConfigurationError,
    TrustsMixinRequired,
)
from trusts.inspect.checks import (
    CHECK_ID_ALONG_RENDERER,
    CHECK_ID_MISSING_DECLARATION,
    CHECK_ID_MIXIN_REQUIRED,
    CHECK_ID_UNBUILDABLE_BACKEND,
    check_along_renderer,
    check_listed_backends,
    check_missing_declarations,
)
from trusts.plan.grammar import Symbol
from trusts.plan.hops import concrete_model, content_model, require_instance
from trusts.inspect.yaml import PolicyYamlError, dump_policy_yaml
from trusts.inspect.snapshot import (
    check_policy_sql_lockfile,
    resolve_lockfile_path,
    write_policy_lock,
)
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)
from trusts.plan.rewrites import bind_once
from trusts.plan.writers import compile_to_q
from trusts.plan.users import assert_persisted_principal
import trusts.plan.rewrites as rewrites


class BuilderSurfaceTest(SimpleTestCase):
    """The condition builder rejects Python statements and loose values."""

    def test_symbols_and_trees_reject_mutation(self):
        row = Symbol('row')
        self.assertEqual(repr(row), 'Symbol(row)')
        self.assertEqual(repr(row.title), 'Symbol(row).title')
        with self.assertRaises(AttributeError):
            row._missing
        with self.assertRaisesRegex(PermissionConditionError, 'Assignment'):
            row.title = 'kept'
        with self.assertRaisesRegex(PermissionConditionError, 'Deletion'):
            del row.title
        with self.assertRaisesRegex(PermissionConditionError, 'not supported'):
            bool(row)
        with self.assertRaises(PermissionConditionError):
            ~row
        with self.assertRaisesRegex(PermissionConditionError, "'in'"):
            'kept' in row.title
        with self.assertRaisesRegex(PermissionConditionError, 'Comparing a condition'):
            row.title == (row.name == 'a')
        tree = Tree('eq', left=row.title._field(), right=Tree('const', value='kept'))
        with self.assertRaisesRegex(PermissionConditionError, 'Assignment'):
            tree.kind = 'ne'
        with self.assertRaisesRegex(PermissionConditionError, 'Deletion'):
            del tree.kind
        with self.assertRaisesRegex(PermissionConditionError, 'not supported'):
            bool(tree)
        negated = ~row.active
        self.assertEqual(negated.kind, 'not')
        self.assertEqual((row.title & row.name).kind, 'and')
        self.assertEqual((row.title | row.name).kind, 'or')
        self.assertEqual(row.title.__rand__(row.name).kind, 'and')
        self.assertEqual(row.title.__ror__(row.name).kind, 'or')
        compared = row.title == 'kept'
        self.assertEqual((compared & compared).kind, 'and')
        self.assertEqual((compared | compared).kind, 'or')
        self.assertEqual(compared.__rand__(compared).kind, 'and')
        self.assertEqual(compared.__ror__(compared).kind, 'or')
        with self.assertRaises(PermissionConditionError):
            row.title.__rand__(1)

    def test_policy_yaml_spells_floats_and_rejects_the_rest(self):
        spelled = dump_policy_yaml({'n': 1e16, 'z': 0.0, 'neg': -0.0, 'one': 1.0})
        self.assertIn(b'1.0e+16', spelled)
        self.assertIn(b'-0.0', spelled)
        self.assertTrue(spelled.endswith(b'\n'))
        refused = (
            {'n': float('nan')},
            {'n': float('inf')},
            [],
            {'sql': 1},
        )
        for document in refused:
            with self.subTest(document=document):
                with self.assertRaises(PolicyYamlError):
                    dump_policy_yaml(document)
        with self.assertRaisesRegex(PolicyYamlError, 'must be a list'):
            dump_policy_yaml({'params': 'no'})
        with self.assertRaisesRegex(PolicyYamlError, 'plain identifier'):
            dump_policy_yaml({'user': {'bad-key': 1}})
        spelled = dump_policy_yaml({
            'params': ['$user.id', 1],
            'user': {'id': 1},
            'sql': 'SELECT 1',
        })
        self.assertIn(b'SELECT 1', spelled)

    def test_user_rules_and_model_roles_fail_closed(self):
        handle = compiler(path='tests.core.coverage-rules')
        refused = (
            ('not-a-name', '*', lambda user: user.is_active),
            ('flag', 'group', lambda user: user.is_active),
            ('flag', '*', 'nope'),
            ('flag', '*', lambda user: user.username),
        )
        for name, on, expr in refused:
            with self.subTest(name=name, on=on):
                with self.assertRaises((
                    TrustsConfigurationError, PermissionConditionError,
                )):
                    handle.set_user_condition(name, expr, on=on)
        with self.assertRaises(TrustsConfigurationError):
            handle.set_user_override(
                'flag', lambda user: user.is_active, on='sponsor',
            )
        with self.assertRaises(TrustsConfigurationError):
            handle.set_user_override('not-name', lambda user: user.is_active)
        with self.assertRaisesRegex(TrustsConfigurationError, 'Expected a model'):
            concrete_model(1)
        with self.assertRaisesRegex(TrustsConfigurationError, 'content must'):
            content_model('sheet')
        with self.assertRaisesRegex(TrustsConfigurationError, 'user must'):
            require_instance('ada', 'user')
        handle = compiler(path='tests.core.coverage-rules-more')
        with self.assertRaisesRegex(TrustsConfigurationError, 'both modes|delegate='):
            handle.register(
                trust=get_user_model(), user='id', delegate='id', content='id',
            )
        with self.assertRaises(TrustsConfigurationError):
            handle.register(
                trust=get_user_model(), delegate='id', content='id',
            )
        self.assertIs(content_model(get_user_model()), get_user_model())
        self.assertIs(
            content_model(get_user_model().objects.all()),
            get_user_model(),
        )


class _GapBackend(TrustModelBackendMixin, ModelBackend):
    """Mixin backend with no app catalog. Every inquiry denies."""


class MixinRequiredBackend(ModelBackend):
    """Constructs nothing. The check must report the mixin error."""

    def __init__(self):
        raise TrustsMixinRequired('needs a mixin')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RegisterRejectionTest(SimpleTestCase):
    """``register()`` fails closed before it stores a bad walk or path."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Node(models.Model):
            title = models.CharField(max_length=20)
            code = models.CharField(max_length=20, unique=True)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                to_field='code', on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField('self', symmetrical=False)

            class Meta:
                app_label = 'trusts_tests'

        class Comment(models.Model):
            node = models.ForeignKey(
                Node, related_name='comments', on_delete=models.CASCADE,
            )
            author = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Link(models.Model):
            parent = models.ForeignKey(
                Node, to_field='code', related_name='as_parent',
                on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Node, related_name='as_child', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class Badge(models.Model):
            class Meta:
                app_label = 'trusts_tests'

        class Sheet(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            content_object = GenericForeignKey()
            badge = models.OneToOneField(
                Badge, null=True, related_name='sheet',
                on_delete=models.CASCADE,
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            title = models.CharField(max_length=20)
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class Bridge(models.Model):
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Node, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        self.Node = Node
        self.Grant = Grant
        self.Bridge = Bridge
        self.Sheet = Sheet

    def _register(self, **extra):
        handle = compiler(path='tests.core.coverage-register')
        kwargs = dict(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='node',
        )
        kwargs.update(extra)
        handle.register(**kwargs)
        return handle

    def test_rejected_walks_store_nothing(self):
        cases = (
            ('mixed-identity', {'along': ('node__parent', 4)}, 'identity'),
            ('edge-too-long', {'along': ('node__parent__parent__parent', 2)}, 'S/C/E'),
            ('m2m-edge', {'along': ('node__tags', 1)}, 'not supported'),
            ('leaves-walk-site', {'along': ('node__comments__author', 1)}, 'walk-site'),
            ('mixed-link-identity', {'along': ('node__as_child__parent', 1)}, 'identity'),
            ('scalar-permission', {'permission': 'title'}, 'scalar'),
            ('missing-permission', {'permission': 'missing'}, 'missing'),
            ('empty-permission', {'permission': ''}, 'not a valid'),
            ('group-permissions-hop', {'permission': None, 'group': 'auth_group__permissions'}, 'do not append'),
            ('empty-group', {'permission': None, 'group': ''}, 'not a valid'),
            ('scalar-group', {'permission': None, 'group': 'title'}, 'single-valued'),
            ('along-number', {'along': (5, 1)}, 'path'),
            ('along-triple', {'along': ('node__parent', 1, 'extra')}, 'pair'),
            ('empty-content', {'content': ''}, 'not a valid'),
            ('dotted-content', {'content': 'node.parent'}, 'not a valid'),
            ('double-underscore', {'content': 'node____parent'}, 'not a valid'),
            ('leading-underscore', {'content': '__node'}, 'not a valid'),
            ('bad-name', {'name': 'has space'}, 'letters'),
            ('bad-description', {'description': 5}, 'string'),
            ('star-args', {
                'trust': self.Bridge,
                'user': None,
                'permission': None,
                'delegate': 'delegate',
                'sponsor': 'sponsor',
                'content': 'node',
                'condition': lambda *args: args[0].delegate == args[0].sponsor,
            }, r'\*args'),
            ('three-args', {
                'trust': self.Bridge,
                'user': None,
                'permission': None,
                'delegate': 'delegate',
                'sponsor': 'sponsor',
                'content': 'node',
                'condition': lambda row, inquiry, extra: row.delegate == row.sponsor,
            }, 'one or two'),
            ('zero-args', {
                'trust': self.Bridge,
                'user': None,
                'permission': None,
                'delegate': 'delegate',
                'sponsor': 'sponsor',
                'content': 'node',
                'condition': lambda: True,
            }, 'one or two'),
        )

        async def _async_condition(row):
            return row.user == row.user

        cases = cases + ((
            'async-condition',
            {'condition': _async_condition},
            'coroutine',
        ),)
        for name, extra, fragment in cases:
            with self.subTest(name=name):
                handle = compiler(path='tests.core.coverage-register-%s' % name)
                with self.assertRaises(TrustsConfigurationError) as raised:
                    kwargs = dict(
                        trust=self.Grant,
                        user='user',
                        permission='permission',
                        content='node',
                    )
                    kwargs.update(extra)
                    if extra.get('permission', True) is None and 'group' in extra:
                        kwargs.pop('permission', None)
                    handle.register(**kwargs)
                if fragment is not None:
                    self.assertRegex(str(raised.exception), fragment)
                self.assertEqual(handle.records, ())
                self.assertEqual(handle._delegation_order, [])

    def test_ref_along_and_path_builders_are_rejected(self):
        with self.assertRaises(TypeError):
            self._register(along=(Ref(self.Grant).node, 1))
        with self.assertRaises(TrustsConfigurationError):
            self._register(content=123)
        with self.assertRaises(TypeError):
            self._register(user=Ref(self.Grant).user)
        with self.assertRaises(PermissionConditionError):
            self._register(content=lambda row: Ref(self.Node))
        handle = compiler(path='tests.core.coverage-empty-ref')
        with self.assertRaises(TrustsConfigurationError):
            handle.register_relation(
                content=Ref(self.Grant).node,
                user=Ref(self.Grant).user,
                permission=Ref(self.Grant),
            )
        self.assertEqual(handle.records, ())

    def test_duplicate_conditioned_along_conflicts_and_reprs(self):
        def _open():
            handle = compiler(path='tests.core.coverage-dup-along')
            handle.register(
                trust=self.Grant,
                user='user',
                permission='permission',
                content='node',
                along=(lambda row: row.node.parent & (row.node.title == 'kept'), 4),
            )
            return handle

        # Parent stores ``code`` (text). The grant hop stores the primary
        # key. That mismatch is rejected; a same-family self-FK is below.
        with self.assertRaises(TrustsConfigurationError):
            _open()

        class Plain(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='kids',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class PlainGrant(models.Model):
            user = models.ForeignKey(
                get_user_model(), on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(Plain, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        handle = compiler(path='tests.core.coverage-dup-plain')
        handle.register(
            trust=PlainGrant,
            user='user',
            permission='permission',
            content='node',
            along=(lambda row: row.node.parent & (row.node.title == 'kept'), 4),
        )
        with self.assertRaises(TrustsConfigurationError) as raised:
            handle.register(
                trust=PlainGrant,
                user='user',
                permission='permission',
                content='node',
                along=(lambda row: row.node.parent & (row.node.title == 'kept'), 2),
            )
        self.assertIn('Conflicting registration', str(raised.exception))
        self.assertIn('AlongWalk', str(raised.exception))
        self.assertIn('condition=', str(raised.exception))
        self.assertEqual(len(handle.records), 1)

    def test_ref_and_along_reject_mutation(self):
        ref = Ref(self.Grant)
        with self.assertRaises(TrustsConfigurationError):
            ref.user = 'no'
        with self.assertRaises(TrustsConfigurationError):
            del ref.user
        with self.assertRaises(TrustsConfigurationError):
            Ref(object())
        with self.assertRaises(TrustsConfigurationError):
            Ref(self.Grant, 'user')
        with self.assertRaises(TrustsConfigurationError):
            Ref(self.Grant, 5)
        self.assertEqual(repr(Ref(self.Grant)), 'Ref(Grant)')
        self.assertEqual(repr(Ref(self.Grant).user), 'Ref(Grant).user')
        self.assertEqual(hash(Ref(self.Grant).user), hash(Ref(self.Grant).user))
        along = Along(Ref(self.Grant).node, 2)
        with self.assertRaises(TrustsConfigurationError):
            along.bound = 3
        with self.assertRaises(TrustsConfigurationError):
            del along.bound
        self.assertEqual(along, Along(Ref(self.Grant).node, 2))
        self.assertEqual(hash(along), hash(Along(Ref(self.Grant).node, 2)))
        self.assertIn('bound=2', repr(along))
        condition = Tree(
            'eq',
            left=Tree('field', root='row', path=('title',)),
            right=Tree('const', value='kept'),
        )
        marked = Along(Ref(self.Grant).node, 2, condition)
        self.assertEqual(hash(marked), hash(Along(Ref(self.Grant).node, 2, condition)))
        self.assertNotEqual(marked, along)
        self.assertIn('condition=', repr(marked))

    def test_rules_are_recorded_before_register_even_if_the_user_model_is_unloaded(self):
        log = Recorder(RegistrationListener())
        with override_settings(AUTH_USER_MODEL='not-a-model'):
            log.register(
                trust=self.Grant,
                user='user',
                permission='permission',
                content='node',
            )
            with self.assertRaisesRegex(
                TrustsConfigurationError, 'before register',
            ):
                log.set_user_condition(
                    'late', lambda user: user.is_active,
                )
        self.assertEqual(len(log._rows), 1)
        with self.assertRaises(TrustsConfigurationError):
            log.register(
                trust=self.Grant,
                user='user',
                permission='title',
                content='node',
            )
        self.assertEqual(len(log._rows), 1)

    def test_walk_shapes_and_path_builders_fail_closed(self):
        User = get_user_model()

        class Plain(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='kids',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class PlainGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            node = models.ForeignKey(Plain, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        class Org(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='units',
                on_delete=models.CASCADE,
            )
            left = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            right = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')

            class Meta:
                app_label = 'trusts_tests'

        class Duo(models.Model):
            org = models.ForeignKey(Org, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        class Meter(models.Model):
            key = models.FloatField(unique=True)
            parent = models.ForeignKey(
                'self', null=True, to_field='key', related_name='lower',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class MeterGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            meter = models.ForeignKey(Meter, to_field='key', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        def reject(fragment, **extra):
            handle = compiler(path='tests.core.coverage-walk-%s' % fragment)
            kwargs = dict(
                trust=PlainGrant,
                user='user',
                permission='permission',
                content='node',
                along=('node__parent', 2),
            )
            kwargs.update(extra)
            with self.assertRaises(TrustsConfigurationError) as raised:
                handle.register(**kwargs)
            self.assertRegex(str(raised.exception), fragment)
            self.assertEqual(handle.records, ())
            self.assertEqual(handle._delegation_order, [])

        async def _async_path(row):
            return row.node.parent

        async def _async_gen(row):
            yield row.node.parent

        def _foreign_symbol(row):
            return Symbol('row', ('node', 'parent'), token=object())

        def _explodes(row):
            raise RuntimeError('path blew up')

        cases = (
            ('missing field', dict(along=('node__missing', 2))),
            ('not a supported S/C/E', dict(along=('node__parent__parent', 2))),
            ('missing field', dict(along=('node__kids__missing', 2))),
            ('not a supported S/C/E', dict(along=('node__kids__kids', 2))),
            ('not a supported S/C/E', dict(along=('node__kids__parent__parent', 2))),
            ('do not share a walk-site', dict(along=('user', 2))),
            ('no edge hop', dict(content='node__kids', along=('node', 2))),
            ('integer in', dict(along=('node__parent', True))),
            ('integer in', dict(along=('node__parent', 0))),
            ('integer in', dict(along=('node__parent', 65))),
            ('integer in', dict(along=('node__parent', 2.5))),
            ('path builder', dict(along=(object(), 2))),
            ('coroutine', dict(along=(_async_path, 2))),
            ('coroutine', dict(along=(_async_gen, 2))),
            ('exactly one positional', dict(along=(lambda row, extra: row.node.parent, 2))),
            ('path builder failed', dict(along=(_explodes, 2))),
            ('empty path', dict(along=(lambda row: row, 2))),
            ('another symbolic root', dict(along=(_foreign_symbol, 2))),
            ('attribute access', dict(along=(lambda row: row.node.title == 'kept', 2))),
            ('exactly one relation path', dict(along=(lambda row: row.node.parent & row.node.kids, 2))),
            ('walked node', dict(along=(lambda row: row.node.parent & (row.title == 'x'), 2))),
            ('walked node', dict(along=(lambda row: row.node.parent & (row.permission.codename == 'x'), 2))),
            ('must name a field', dict(along=(lambda row: row.node.parent & (row.node == row.node), 2))),
            ('scalar field', dict(content='node__title', along=('node__parent', 2))),
            ('path, bound', dict(along=5)),
            ('letters and underscores', dict(name='has space')),
            ('must be a string', dict(description=5)),
        )
        for fragment, extra in cases:
            with self.subTest(fragment=fragment, keys=tuple(extra)):
                reject(fragment, **extra)

        opened = compiler(path='tests.core.coverage-e-shape')
        record = opened.register(
            trust=PlainGrant,
            user='user',
            permission='permission',
            content='node',
            along=('node__kids__parent', 2),
        )
        self.assertEqual(record.along.shape, 'E')
        self.assertEqual(len(opened.records), 1)

        both = compiler(path='tests.core.coverage-two-conditions')
        stored = both.register(
            trust=PlainGrant,
            user='user',
            permission='permission',
            content='node',
            along=(
                lambda row: row.node.parent & (row.node.title == 'a') & (
                    row.node.title == 'b'
                ),
                2,
            ),
        )
        self.assertIsNotNone(stored.along.condition)
        coalesced = compiler(path='tests.core.coverage-coalesce-walk')
        with self.assertRaisesRegex(PermissionConditionError, 'not supported'):
            coalesced.register(
                trust=PlainGrant,
                user='user',
                permission='permission',
                content='node',
                along=(
                    lambda row: row.node.parent & (
                        Coalesce(row.node.title, 'x') == 'kept'
                    ),
                    2,
                ),
            )

        with self.assertRaisesRegex(TrustsConfigurationError, 'exactly one'):
            compiler(path='tests.core.coverage-via-none').register(
                trust=self.Bridge,
                delegate='delegate',
                sponsor='sponsor',
                content='node',
                via=('node__parent', 2),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, 'exactly one'):
            compiler(path='tests.core.coverage-via-both').register(
                trust=Duo,
                delegate='org__left',
                sponsor='org__right',
                content='org',
                via=('org__parent', 2),
            )
        with self.assertRaisesRegex(TrustsConfigurationError, 'not a V1'):
            compiler(path='tests.core.coverage-float-ident').register(
                trust=MeterGrant,
                user='user',
                permission='permission',
                content='meter',
                along=('meter__parent', 2),
            )

    def test_a_bare_root_and_a_compared_condition_are_rejected(self):
        handle = compiler()
        with self.assertRaisesRegex(PermissionConditionError, 'root without a field'):
            handle.add_named_filter(
                self.Node, 'bare', lambda user, permission, obj: obj,
            )
        self.assertEqual(handle.records, ())

    def test_generic_foreign_key_permission_is_rejected(self):
        User = get_user_model()

        class Mark(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            node = models.ForeignKey(self.Node, on_delete=models.CASCADE)
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            content_object = GenericForeignKey()

            class Meta:
                app_label = 'trusts_tests'

        handle = compiler(path='tests.core.coverage-gfk')
        with self.assertRaisesRegex(TrustsConfigurationError, 'generic foreign key'):
            handle.register(
                trust=Mark,
                user='user',
                permission='content_object',
                content='node',
            )
        self.assertEqual(handle.records, ())

    def test_empty_group_gfk_and_reverse_paths_are_rejected(self):
        cases = (
            dict(trust=self.Grant, user='', permission='permission', content='node'),
            dict(
                trust=self.Grant, user='user', permission='permission',
                content='node', group='',
            ),
            dict(
                trust=self.Grant, user='user', permission='permission',
                content='node', group='missing',
            ),
            dict(
                trust=self.Sheet, user='auth_group', permission='content_object',
                content='node',
            ),
            dict(
                trust=self.Sheet, user='auth_group', permission='badge',
                content='content_object',
            ),
            dict(
                trust=self.Grant, user='user', permission='permission',
                content='node__tags',
            ),
        )
        for kwargs in cases:
            shown = {key: value for key, value in kwargs.items() if key != 'trust'}
            with self.subTest(**shown):
                handle = compiler(
                    path='tests.core.coverage-more-%s' % abs(hash(tuple(shown.items()))),
                )
                with self.assertRaises(TrustsConfigurationError):
                    handle.register(**kwargs)
                self.assertEqual(handle.records, ())
        handle = compiler(path='tests.core.coverage-user-groups')
        with self.assertRaisesRegex(
            TrustsConfigurationError, 'terminates on auth.Group',
        ):
            handle.register(
                trust=self.Grant, user='user__groups',
                permission='permission', content='node',
            )
        self.assertEqual(handle.records, ())


class _Outside(TrustModelBackendMixin, ModelBackend):
    pass


_Outside.__module__ = 'not_installed.backends'


class UncatalogedBackendTest(TestCase):
    """A mixin backend with no catalog does not grant."""

    def test_every_inquiry_is_empty(self):
        User = get_user_model()
        backend = _Outside()
        user = User(pk=1)
        self.assertIsNone(backend.walk_questions(object()))
        self.assertIs(backend.has_perm(user, 'auth.view_user', user), False)
        self.assertEqual(backend.get_all_permissions(user, user), set())
        self.assertEqual(backend.get_group_permissions(user, user), set())
        self.assertIsNone(backend.permitted_users_predicate(user, 'auth.view_user'))
        self.assertIsNone(backend.authorized_grant_q(User.objects.none(), user, user))
        self.assertIsNone(backend.permitted_grant_q(
            User.objects.none(), user, 'auth.view_user',
        ))
        self.assertEqual(
            list(backend.filter_permitted(User.objects.none(), user, 'not-a-code')),
            [],
        )
        self.assertEqual(
            list(backend.filter_permitted(User.objects.none(), user, 'auth.view_user')),
            [],
        )
        self.assertEqual(
            list(backend.filter_by_permitted_content(
                User.objects.none(), user, user, content=user,
            )),
            [],
        )
        document = backend.policy_document()
        self.assertEqual(document['backends'], [])


class _NotAQuery(object):
    query = 'rows'


class _NoQuote(object):
    def compile(self, node):
        return '', ()


class _NoCompile(object):
    def quote_name(self, name):
        return '"%s"' % name


class _Ops(object):
    pass


class _Conn(object):
    ops = _Ops()


class _NoConditional(object):
    connection = _Conn()

    def quote_name(self, name):
        return '"%s"' % name

    def compile(self, node):
        return '', ()


class _EmptyMessage(Exception):
    def __str__(self):
        return ''


def _install_compiler(compiler):
    def _mutate(qs):
        qs.query.get_compiler = lambda using=None, connection=None: compiler
    return _mutate


def _bad_f_name(qs):
    bad = F('email')
    bad.name = 1
    lookup = qs.query.where.children[0]
    lookup.rhs = bad
    lookup.rhs_is_direct_value = lambda: False


def _rhs_method_missing(qs):
    qs.query.where.children[0].rhs_is_direct_value = 1


def _no_create(qs):
    node = qs.query.where

    class _NoCreate(type(node)):
        create = None

    node.__class__ = _NoCreate


def _raise_during_compile(qs):
    def _get(using=None, connection=None):
        raise ValueError('compiler failed')
    qs.query.get_compiler = _get


def _raise_without_message(qs):
    def _get(using=None, connection=None):
        raise _EmptyMessage()
    qs.query.get_compiler = _get


def _strip_rhs(qs):
    lookup = qs.query.where.children[0]
    if hasattr(lookup, 'rhs'):
        del lookup.rhs


def _rename_lookup(qs):
    lookup = qs.query.where.children[0]
    lookup.lookup_name = 1


class _SourceList(object):
    def get_source_expressions(self):
        return 'no'


class _NoSetter(object):
    def get_source_expressions(self):
        return [1]


def _combined_problem(qs):
    User = get_user_model()
    inner = User.objects.all()
    inner.query.where.children.append(('username', 'x', 'extra'))
    qs.query.combined_queries = (inner.query,)


class BindOnceShapeTest(TestCase):
    """A query this pass does not understand is returned unchanged."""

    def test_unresolved_pairs_keep_the_same_rows(self):
        User = get_user_model()
        user = User.objects.create_user('bind-shape', password='x')
        other = User.objects.create_user('bind-other', password='x', is_active=False)
        cases = (
            Q(is_active=True),
            Q(id=user.pk),
            Q(username='bind-shape'),
            Q(pk=user.pk),
        )
        for predicate in cases:
            with self.subTest(predicate=predicate):
                prepared, extra = bind_once(
                    User.objects.all(), predicate, user_model=User,
                )
                self.assertEqual(
                    set(prepared.filter(extra).values_list('pk', flat=True)),
                    set(User.objects.filter(predicate).values_list('pk', flat=True)),
                )
        self.assertNotIn(
            other.pk,
            set(User.objects.filter(is_active=True).values_list('pk', flat=True)),
        )

    def test_content_type_and_permission_keys_keep_the_same_rows(self):
        User = get_user_model()
        ct = ContentType.objects.get_for_model(User)
        perm = Permission.objects.filter(content_type=ct).first()
        cases = (
            (ContentType.objects.all(), Q(app_label=ct.app_label)),
            (ContentType.objects.all(), Q(model=ct.model)),
            (Permission.objects.all(), Q(content_type_id=ct.pk)),
            (Permission.objects.all(), Q(content_type__app_label=ct.app_label)),
            (Permission.objects.all(), Q(content_type__model=ct.model)),
            (Permission.objects.all(), Q(codename=perm.codename)),
            (Permission.objects.all(), Q(id=perm.pk)),
            (ContentType.objects.all(), Q(pk=ct.pk)),
            (ContentType.objects.all(), Q(id=ct.pk)),
            (User.objects.all(), Q(username=F('email'))),
            (User.objects.all(), Q(email=F('username'))),
        )
        for queryset, predicate in cases:
            with self.subTest(predicate=predicate):
                prepared, extra = bind_once(
                    queryset, predicate, user_model=User,
                )
                self.assertEqual(
                    set(prepared.filter(extra).values_list('pk', flat=True)),
                    set(queryset.filter(predicate).values_list('pk', flat=True)),
                )

    def test_combined_queries_and_subqueries_keep_the_same_rows(self):
        User = get_user_model()
        user = User.objects.create_user('bind-or', password='x')
        User.objects.create_user('bind-or-other', password='x', is_staff=True)
        combined = User.objects.filter(username='bind-or') | User.objects.filter(
            is_staff=True,
        )
        prepared, extra = bind_once(
            combined, Q(is_active=True), user_model=User,
        )
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            set(combined.filter(is_active=True).values_list('pk', flat=True)),
        )
        self.assertIn(user.pk, set(prepared.filter(extra).values_list('pk', flat=True)))
        annotated = User.objects.annotate(shifted=F('id') + 1)
        prepared, extra = bind_once(
            annotated, Q(shifted__gt=0), user_model=User,
        )
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            set(annotated.filter(shifted__gt=0).values_list('pk', flat=True)),
        )
        lowered = Q(username=SqlLower(F('username')))
        prepared, extra = bind_once(User.objects.all(), lowered, user_model=User)
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            set(User.objects.filter(lowered).values_list('pk', flat=True)),
        )
        staff = Q(is_active=F('is_staff'))
        prepared, extra = bind_once(User.objects.all(), staff, user_model=User)
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            set(User.objects.filter(staff).values_list('pk', flat=True)),
        )
        more = (
            Q(username=SqlCoalesce(F('username'), Value('x'))),
            Q(username=Concat(F('username'), Value(''))),
            ~Q(username='missing-user'),
            Q(id__gt=0) & ~Q(is_staff=True),
        )
        for predicate in more:
            with self.subTest(predicate=predicate):
                prepared, extra = bind_once(
                    User.objects.all(), predicate, user_model=User,
                )
                self.assertEqual(
                    set(prepared.filter(extra).values_list('pk', flat=True)),
                    set(User.objects.filter(predicate).values_list('pk', flat=True)),
                )
        again, extra = bind_once(
            prepared, Q(is_active=True), user_model=User,
        )
        self.assertEqual(
            set(again.filter(extra).values_list('pk', flat=True)),
            set(prepared.filter(is_active=True).values_list('pk', flat=True)),
        )
        nested = User.objects.filter(
            pk__in=User.objects.filter(username='bind-or').values('pk'),
        )
        prepared, extra = bind_once(nested, Q(), user_model=User)
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            {user.pk},
        )

    def test_unexpected_structure_returns_the_original_queryset(self):
        User = get_user_model()
        saved = rewrites._warned
        rewrites._warned = False
        try:
            mutations = (
                ('alias-map', lambda qs: setattr(qs.query, 'alias_map', [])),
                ('alias-refcount', lambda qs: setattr(qs.query, 'alias_refcount', [])),
                ('alias-entry', lambda qs: setattr(
                    qs.query, 'alias_refcount', {1: 'no'},
                )),
                ('table-map', lambda qs: setattr(qs.query, 'table_map', [])),
                ('table-entry', lambda qs: setattr(
                    qs.query, 'table_map', {'auth_user': 'no'},
                )),
                ('where', lambda qs: setattr(qs.query, 'where', None)),
                ('annotations', lambda qs: setattr(qs.query, 'annotations', [])),
                ('annotation-key', lambda qs: setattr(
                    qs.query, 'annotations', {1: None},
                )),
                ('combined', lambda qs: setattr(qs.query, 'combined_queries', [])),
                ('annotation-value', lambda qs: setattr(
                    qs.query, 'annotations', {'x': object()},
                )),
                ('missing-clone', lambda qs: setattr(qs.query, 'clone', None)),
                ('combined-part', lambda qs: setattr(
                    qs.query, 'combined_queries', ('no',),
                )),
                ('where-children', lambda qs: setattr(
                    qs.query.where, 'children', None,
                )),
                ('where-connector', lambda qs: setattr(
                    qs.query.where, 'connector', 1,
                )),
                ('where-negated', lambda qs: setattr(
                    qs.query.where, 'negated', None,
                )),
                ('where-triple', lambda qs: qs.query.where.children.append(
                    ('username', 'x', 'extra'),
                )),
                ('lookup-name', _rename_lookup),
                ('where-object', lambda qs: qs.query.where.children.append(object())),
                ('source-list', lambda qs: qs.query.where.children.append(_SourceList())),
                ('no-setter', lambda qs: qs.query.where.children.append(_NoSetter())),
                ('combined-problem', _combined_problem),
                ('missing-rhs', _strip_rhs),
                ('no-quote', _install_compiler(_NoQuote())),
                ('no-compile', _install_compiler(_NoCompile())),
                ('no-conditional', _install_compiler(_NoConditional())),
                ('bad-f-name', _bad_f_name),
                ('rhs-method', _rhs_method_missing),
                ('no-create', _no_create),
                ('compiler-error', _raise_during_compile),
                ('compiler-empty', _raise_without_message),
            )
            for name, mutate in mutations:
                with self.subTest(name=name):
                    rewrites._warned = False
                    original = User.objects.filter(is_active=True)
                    mutate(original)
                    with self.assertLogs('trusts', level='WARNING') as logged:
                        returned = bind_once(original, user_model=User)
                    self.assertIs(returned, original)
                    self.assertIn('unchanged', logged.output[0])
            rewrites._warned = False
            foreign = _NotAQuery()
            with self.assertLogs('trusts', level='WARNING') as logged:
                returned = bind_once(foreign, user_model=User)
            self.assertIs(returned, foreign)
            self.assertIn('not a Query', logged.output[0])
        finally:
            rewrites._warned = saved


def _drop_model(model):
    label = model._meta.app_label
    name = model._meta.model_name
    app_models = django_apps.all_models.get(label)
    if app_models is not None:
        app_models.pop(name, None)
    django_apps.clear_cache()


class MissingDeclarationCheckTest(SimpleTestCase):
    """Content and Junction without a catalog record are trusts.E003."""

    def test_empty_catalog_list_reports_nothing(self):
        with override_settings(AUTHENTICATION_BACKENDS=(
            'django.contrib.auth.backends.ModelBackend',
        )):
            self.assertEqual(check_missing_declarations(None), [])

    def test_uncovered_content_and_malformed_junction_are_reported(self):
        created = []

        class Content(models.Model):
            class Meta:
                abstract = True
                app_label = 'trusts'

        class Junction(models.Model):
            class Meta:
                abstract = True
                app_label = 'trusts'

        class CovArticle(Content):
            title = models.CharField(max_length=10)

            class Meta:
                app_label = 'trusts_tests'

        class CovBrokenLink(Junction):
            class Meta:
                app_label = 'trusts_tests'

            @classmethod
            def get_content_model(cls):
                raise RuntimeError('no content')

        class CovPlainLink(Junction):
            class Meta:
                app_label = 'trusts_tests'

            @classmethod
            def get_content_model(cls):
                return 'article'

        class CovArticleLink(Junction):
            class Meta:
                app_label = 'trusts_tests'

            @classmethod
            def get_content_model(cls):
                return CovArticle

        created.extend((
            Content, Junction, CovArticle, CovBrokenLink,
            CovPlainLink, CovArticleLink,
        ))
        try:
            messages = [
                message for message in check_missing_declarations(None)
                if message.id == CHECK_ID_MISSING_DECLARATION
            ]
            text = ' '.join(message.msg for message in messages)
            self.assertIn('CovArticle', text)
            self.assertIn('CovBrokenLink', text)
            self.assertIn('malformed', text)
            self.assertIn('CovPlainLink', text)
            self.assertIn('did not return a Django model', text)
            self.assertIn('CovArticleLink', text)
            labels = [
                getattr(getattr(message.obj, '_meta', None), 'label', '')
                for message in messages
            ]
            self.assertEqual(labels, sorted(labels))
        finally:
            for model in created:
                _drop_model(model)

    def test_covered_content_and_proxy_are_not_reported(self):
        User = get_user_model()

        class Content(models.Model):
            class Meta:
                abstract = True
                app_label = 'trusts'

        class CovArticle(Content):
            title = models.CharField(max_length=10)

            class Meta:
                app_label = 'trusts_tests'

        class CovArticleProxy(CovArticle):
            class Meta:
                proxy = True
                app_label = 'trusts_tests'

        class CovOther(Content):
            title = models.CharField(max_length=10)

            class Meta:
                app_label = 'trusts_tests'

        class CovGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
            article = models.ForeignKey(CovArticle, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'

        created = (Content, CovArticle, CovArticleProxy, CovOther, CovGrant)
        handle = compiler(path='tests.core.coverage-covered')
        handle.register(
            trust=CovGrant, user='user', permission='permission', content='article',
        )
        try:
            with published_class_catalog(
                HostTrustModelBackend, handle,
            ), override_settings(AUTHENTICATION_BACKENDS=(
                'tests.kernel_host.backends.HostTrustModelBackend',
            )):
                messages = [
                    message for message in check_missing_declarations(None)
                    if message.id == CHECK_ID_MISSING_DECLARATION
                ]
            text = ' '.join(message.msg for message in messages)
            self.assertNotIn('trusts_tests.CovArticle ', text)
            self.assertIn('trusts_tests.CovOther', text)
            self.assertNotIn('CovArticleProxy', text)
        finally:
            for model in created:
                _drop_model(model)

    def test_unbuildable_and_catalogless_backends_are_reported(self):
        with override_settings(AUTHENTICATION_BACKENDS=(
            'django.contrib.auth.backends.ModelBackend',
            'tests.core.test_coverage_behavior.MissingBackend',
            'tests.core.test_coverage_behavior.MixinRequiredBackend',
            'tests.core.test_coverage_behavior._GapBackend',
        )):
            messages = check_listed_backends(None)
            self.assertEqual(check_missing_declarations(None), [])
            self.assertEqual(
                check_along_renderer(None, databases=['default']), [],
            )
        by_id = {}
        for message in messages:
            by_id.setdefault(message.id, []).append(message.msg)
        self.assertTrue(any(
            'MissingBackend' in msg and 'could not be built' in msg
            for msg in by_id[CHECK_ID_UNBUILDABLE_BACKEND]
        ))
        self.assertTrue(any(
            'needs a mixin' in msg
            for msg in by_id[CHECK_ID_MIXIN_REQUIRED]
        ))


class PolicyLockPermissionTest(SimpleTestCase):
    """An unreadable lock path fails closed and does not write."""

    def test_unreadable_parent_is_permission_denied(self):
        parent = Path(tempfile.mkdtemp(prefix='trusts-lock-'))
        target = parent / 'policy.lock.yaml'
        try:
            os.chmod(parent, 0)
            location = resolve_lockfile_path(override=str(target))
            self.assertEqual(location.state, 'permission')
            with self.assertRaisesRegex(TrustsConfigurationError, 'permission denied'):
                write_policy_lock(b'lock: 1\n', override=str(target))
        finally:
            os.chmod(parent, stat.S_IRWXU)
            self.assertFalse(target.exists())
            parent.rmdir()

    def test_lock_paths_fail_closed_until_the_parent_is_a_directory(self):
        parent = Path(tempfile.mkdtemp(prefix='trusts-lock-'))
        target = parent / 'policy.lock.yaml'
        try:
            with self.assertRaises(TypeError):
                write_policy_lock('not-bytes', override=str(target))
            for bad in (True, 5, 'relative.lock', Path('relative.lock')):
                with self.subTest(bad=bad):
                    with self.assertRaises(TrustsConfigurationError):
                        resolve_lockfile_path(override=bad)
            missing = parent / 'absent' / 'policy.lock.yaml'
            with self.assertRaisesRegex(TrustsConfigurationError, 'missing'):
                write_policy_lock(b'lock: 1\n', override=str(missing))
            blocker = parent / 'not-a-dir'
            blocker.write_text('file')
            nested = blocker / 'policy.lock.yaml'
            with self.assertRaisesRegex(TrustsConfigurationError, 'not a directory'):
                write_policy_lock(b'lock: 1\n', override=str(nested))
            written = write_policy_lock(b'lock: 1\n', override=str(target))
            self.assertEqual(written, target)
            self.assertEqual(target.read_bytes(), b'lock: 1\n')
            again = write_policy_lock(b'lock: 2\n', override=str(target))
            self.assertEqual(again.read_bytes(), b'lock: 2\n')
            target.unlink()
            target.mkdir()
            with self.assertRaisesRegex(TrustsConfigurationError, 'directory'):
                write_policy_lock(b'lock: 3\n', override=str(target))
        finally:
            if target.is_dir():
                target.rmdir()
            elif target.exists():
                target.unlink()
            blocker = parent / 'not-a-dir'
            if blocker.exists():
                blocker.unlink()
            parent.rmdir()

    def test_relative_base_dir_requires_an_explicit_lock_path(self):
        from trusts.inspect.snapshot import resolve_policy_database

        with override_settings(BASE_DIR='relative', TRUSTS_POLICY_LOCKFILE=None):
            with self.assertRaisesRegex(TrustsConfigurationError, 'BASE_DIR'):
                resolve_lockfile_path()
        with override_settings(TRUSTS_POLICY_DATABASE='missing-alias'):
            with self.assertRaisesRegex(TrustsConfigurationError, 'DATABASES'):
                resolve_policy_database()
        with override_settings(TRUSTS_POLICY_DATABASE=True):
            with self.assertRaisesRegex(TrustsConfigurationError, 'DATABASES'):
                resolve_policy_database()
        self.assertEqual(resolve_policy_database('default'), 'default')

    def test_conventional_absence_is_not_a_lock_failure(self):
        parent = Path(tempfile.mkdtemp(prefix='trusts-lock-'))
        try:
            with override_settings(BASE_DIR=parent, TRUSTS_POLICY_LOCKFILE=None):
                self.assertEqual(check_policy_sql_lockfile(None), [])
            missing = parent / 'missing-base'
            with override_settings(BASE_DIR=missing, TRUSTS_POLICY_LOCKFILE=None):
                self.assertEqual(check_policy_sql_lockfile(None), [])
            blocker = parent / 'not-dir'
            blocker.write_text('x')
            with override_settings(BASE_DIR=blocker, TRUSTS_POLICY_LOCKFILE=None):
                self.assertEqual(check_policy_sql_lockfile(None), [])
            explicit = parent / 'explicit.lock.yaml'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(explicit)):
                missing_file = check_policy_sql_lockfile(None)
            self.assertTrue(any('missing' in message.msg for message in missing_file))
            explicit.write_bytes(b'not-the-policy\n')
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(explicit)):
                drifted = check_policy_sql_lockfile(None)
            self.assertTrue(any('differ' in message.msg for message in drifted))
            explicit.unlink()
            explicit.mkdir()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(explicit)):
                directory = check_policy_sql_lockfile(None)
            self.assertTrue(any('directory' in message.msg for message in directory))
        finally:
            explicit = parent / 'explicit.lock.yaml'
            blocker = parent / 'not-dir'
            if explicit.is_dir():
                explicit.rmdir()
            elif explicit.exists():
                explicit.unlink()
            if blocker.exists():
                blocker.unlink()
            parent.rmdir()


def _tables(*model_classes):
    from contextlib import contextmanager

    @contextmanager
    def _open():
        with connection.schema_editor() as editor:
            for model in model_classes:
                editor.create_model(model)
        try:
            yield
        finally:
            with connection.schema_editor() as editor:
                for model in reversed(model_classes):
                    editor.delete_model(model)

    return _open()


def _permission(model, codename, name=None):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': name or codename},
    )
    return permission


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterAgreementTest(TransactionTestCase):
    """Forward and reverse inquiries agree on permission and user filters."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Desk(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_desk'

        class NoteQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Note(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            desk = models.ForeignKey(
                Desk, null=True, db_constraint=False, on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(NoteQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_note'

        class Grant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_grant'

        self.User = User
        self.Desk = Desk
        self.Note = Note
        self.Grant = Grant
        opened = _tables(Desk, Note, Grant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        self.change = _permission(Note, 'change_covnote', name='Change note')
        self.other = _permission(Note, 'view_covnote', name='View note')
        self.code = 'trusts_tests.change_covnote'
        self.alice = User.objects.create_user('cov-alice', password='x')
        self.bob = User.objects.create_user('cov-bob', password='x')
        self.group = Group.objects.create(name='cov-readers')
        self.alice.groups.add(self.group)
        self.ops = Desk.objects.create(name='ops')
        self.lab = Desk.objects.create(name='lab')
        self.notes = {
            'ops': Note.objects.create(title='open', desk=self.ops),
            'lab': Note.objects.create(title='open', desk=self.lab),
            'bare': Note.objects.create(title='shut', desk=None),
        }
        dangling = Note.objects.create(title='open', desk=None)
        Note.objects.filter(pk=dangling.pk).update(desk_id=2147483646)
        self.notes['dangling'] = Note.objects.get(pk=dangling.pk)
        for note in self.notes.values():
            Grant.objects.create(user=self.alice, note=note, permission=self.change)
            Grant.objects.create(user=self.bob, note=note, permission=self.change)

    def _handle(self, name, predicate):
        handle = compiler(path='tests.core.coverage-filter-%s' % name)
        handle.add_named_filter(self.Note, name, predicate)
        handle.register(
            trust=self.Grant,
            user='user',
            permission='permission',
            content='note',
        )
        return handle

    def _answers(self, handle, user, note, code, *, conditions=()):
        filtered = '%s:%s' % (code, conditions[0]) if conditions else code
        with published_class_catalog(
            HostTrustModelBackend, handle,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            has = user.has_perm(filtered, note)
            permitted = note.pk in set(self.Note.objects.permitted(
                code, user, conditions=conditions,
            ).values_list('pk', flat=True))
            reached = user.pk in set(note.get_permitted_users(
                filtered,
            ).values_list('pk', flat=True))
            by_instance = note.pk in set(self.Note.objects.permitted(
                self.change if code.endswith('change_covnote') else self.other,
                user, conditions=conditions,
            ).values_list('pk', flat=True))
        return has, permitted, reached, by_instance

    def _agree(self, handle, user, note, allowed, *, name, code=None):
        code = self.code if code is None else code
        has, permitted, reached, by_instance = self._answers(
            handle, user, note, code, conditions=(name,),
        )
        self.assertEqual(
            (has, permitted, reached, by_instance),
            (allowed, allowed, allowed, allowed),
            note.title if hasattr(note, 'title') else note,
        )

    def test_permission_fields_and_user_membership_agree(self):
        code_filter = self._handle(
            'code', lambda user, permission, obj: permission.codename == 'change_covnote',
        )
        app_filter = self._handle(
            'app', lambda user, permission, obj: permission.app_label == 'trusts_tests',
        )
        whole = self._handle(
            'whole',
            lambda user, permission, obj: permission == 'trusts_tests.change_covnote',
        )
        desk = self._handle(
            'desk', lambda user, permission, obj: obj.desk.name == 'ops',
        )
        member = self._handle(
            'member', lambda user, permission, obj: user.groups.contains(self.group),
        )
        both = self._handle(
            'both',
            lambda user, permission, obj: (
                user.groups.contains(self.group)
                & (permission.codename == 'change_covnote')
            ),
        )
        either = self._handle(
            'either',
            lambda user, permission, obj: (
                user.groups.contains(self.group) | (obj.title == 'shut')
            ),
        )
        note = self.notes['ops']
        self._agree(code_filter, self.alice, note, True, name='code')
        self._agree(app_filter, self.alice, note, True, name='app')
        self._agree(whole, self.alice, note, True, name='whole')
        self._agree(desk, self.alice, self.notes['ops'], True, name='desk')
        self._agree(desk, self.alice, self.notes['lab'], False, name='desk')
        self._agree(desk, self.alice, self.notes['bare'], False, name='desk')
        self._agree(desk, self.alice, self.notes['dangling'], False, name='desk')
        self._agree(member, self.alice, note, True, name='member')
        self._agree(member, self.bob, note, False, name='member')
        self._agree(both, self.alice, note, True, name='both')
        self._agree(both, self.bob, note, False, name='both')
        self._agree(either, self.bob, self.notes['bare'], True, name='either')
        self._agree(either, self.bob, self.notes['ops'], False, name='either')
        self._agree(either, self.alice, self.notes['ops'], True, name='either')

        wrong = self._handle(
            'wrong', lambda user, permission, obj: permission.codename == 'missing',
        )
        self._agree(wrong, self.alice, note, False, name='wrong')

        rejected = compiler(path='tests.core.coverage-permission-name')
        with self.assertRaises(PermissionConditionError) as raised:
            rejected.add_named_filter(
                self.Note, 'bad',
                lambda user, permission, obj: permission.name == 'Change note',
            )
        self.assertIn('cannot traverse attributes in V1', str(raised.exception))
        self.assertEqual(rejected.records, ())

    def test_null_membership_does_not_grant(self):
        handle = compiler(path='tests.core.coverage-null-member')
        handle.add_named_filter(
            self.Note, 'empty_or',
            lambda user, permission, obj: (
                user.groups.contains(None) | (obj.title == 'shut')
            ),
        )
        handle.add_named_filter(
            self.Note, 'empty_and',
            lambda user, permission, obj: (
                user.groups.contains(None) & (obj.title == 'open')
            ),
        )
        handle.register(
            trust=self.Grant, user='user', permission='permission', content='note',
        )
        self._agree(handle, self.alice, self.notes['bare'], True, name='empty_or')
        self._agree(handle, self.alice, self.notes['ops'], False, name='empty_or')
        self._agree(handle, self.alice, self.notes['ops'], False, name='empty_and')

    def test_lower_and_coalesce_agree_on_the_title(self):
        lowered = self._handle(
            'low', lambda user, permission, obj: Lower(obj.title) == 'open',
        )
        self._agree(lowered, self.alice, self.notes['ops'], True, name='low')
        self._agree(lowered, self.alice, self.notes['bare'], False, name='low')
        with self.assertRaisesRegex(PermissionConditionError, 'not supported'):
            self._handle(
                'fill',
                lambda user, permission, obj: Coalesce(obj.title, 'shut') == 'open',
            )
        filled = self._handle(
            'filled',
            lambda user, permission, obj: (
                Coalesce(obj.title, Value('shut')) == 'open'
            ),
        )
        self._agree(filled, self.alice, self.notes['ops'], True, name='filled')
        self._agree(filled, self.alice, self.notes['bare'], False, name='filled')
        document = render_configured_policy(lowered)
        self.assertIn(b'LOWER', document.upper())

    def test_a_permission_id_is_not_a_group(self):
        handle = compiler(path='tests.core.coverage-permission-id')
        with self.assertRaises(PermissionConditionError):
            handle.add_named_filter(
                self.Note, 'perm_pk',
                lambda user, permission, obj: user.groups.contains(permission.id),
            )
        self.assertEqual(handle.records, ())

    def test_a_missing_desk_does_not_grant(self):
        handle = self._handle(
            'desk_user',
            lambda user, permission, obj: obj.desk.name == user.username,
        )
        self._agree(
            handle, self.alice, self.notes['ops'], False, name='desk_user',
        )
        self._agree(
            handle, self.alice, self.notes['dangling'], False, name='desk_user',
        )

    def test_a_title_filter_renders_to_policy_sql(self):
        handle = self._handle(
            'open', lambda user, permission, obj: obj.title == 'open',
        )
        document = render_configured_policy(handle)
        self.assertIn(b'trusts_tests.Note', document)
        self.assertIn(b'title=\\"open\\"', document)

    def test_group_pk_is_not_the_user_pk(self):
        allowed = self.group.pk == self.alice.pk
        handle = self._handle(
            'same_pk',
            lambda user, permission, obj: user.groups.contains(user.id),
        )
        self._agree(
            handle, self.alice, self.notes['ops'], allowed, name='same_pk',
        )

    def test_a_filter_cannot_carry_a_queryset_connection_or_callable(self):
        refused = (
            self.Note.objects.all(),
            connection,
            (lambda: None),
        )
        for value in refused:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(PermissionConditionError):
                    self._handle(
                        'bad',
                        lambda user, permission, obj, value=value: (
                            obj.title == value
                        ),
                    )

    def test_a_codename_is_not_a_group_member(self):
        with self.assertRaisesRegex(PermissionConditionError, 'incompatible'):
            self._handle(
                'code_member',
                lambda user, permission, obj: user.groups.contains(
                    permission.codename,
                ),
            )

    def test_catalog_rejects_an_inquiry_it_cannot_read(self):
        handle = self._handle(
            'plain', lambda user, permission, obj: obj.title == 'open',
        )
        catalog = built_catalog(handle)
        note = self.notes['ops']
        unsaved_note = self.Note(title='open')
        unsaved_perm = Permission(codename='change_covnote')
        self.assertFalse(catalog.has_permission(None, note, self.change))
        self.assertFalse(catalog.has_permission(self.alice, note, unsaved_perm))
        self.assertFalse(catalog.has_permission(self.alice, unsaved_note, self.change))
        self.assertTrue(catalog.has_permission(
            self.alice, self.Note.objects.filter(pk=note.pk), self.change,
        ))
        self.assertFalse(catalog.has_permission(
            self.alice, self.Note.objects.filter(title='missing'), self.change,
        ))
        self.assertEqual(catalog.permissions_for(None, note), ())
        self.assertEqual(catalog.permissions_for(self.alice, unsaved_note), ())
        self.assertFalse(catalog.has_perm(None, self.code, note))
        self.assertFalse(catalog.has_perm(self.alice, self.code, unsaved_note))
        self.assertIs(
            catalog.filter_authorized('rows', self.alice, self.change),
            'rows',
        )
        self.assertEqual(list(catalog.filter_authorized(
            [note], self.alice, self.change,
        )), [])
        self.assertIs(
            catalog.filter_authorized(note, self.alice, self.change),
            note,
        )
        self.assertEqual(list(catalog.filter_by_permitted_content(
            self.Note.objects.all(), self.alice, self.change,
            content=note, conditions=123,
        )), [])
        self.assertEqual(list(catalog.filter_by_permitted_content(
            self.Note.objects.all(), self.alice, unsaved_perm, content=note,
        )), [])
        self.assertEqual(list(catalog._question_named_filter_grant(
            self.Note, 'plain', None, self.code,
        )), [])
        self.assertEqual(list(catalog._question_named_filter_grant(
            self.Note, 'plain', self.alice, unsaved_perm,
        )), [])
        self.assertIsNone(catalog._question_conditional_has_perm(
            self.alice, unsaved_note, self.code, 'plain',
        ))
        self.assertIsNone(catalog._question_conditional_has_perm(
            self.alice, note, self.code, '',
        ))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ReversePrincipalTest(TransactionTestCase):
    """Reverse inquiry fails closed on a principal SQL cannot match."""

    def test_concrete_anonymous_and_authenticated_columns_are_enforced(self):
        class FlagNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag_note'

        class Principal(models.Model):
            name = models.CharField(max_length=40)
            is_anonymous = models.BooleanField(default=False)
            is_authenticated = models.BooleanField(default=True)
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag_user'

        class Grant(models.Model):
            user = models.ForeignKey(Principal, on_delete=models.CASCADE)
            note = models.ForeignKey(FlagNote, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag_grant'

        opened = _tables(FlagNote, Principal, Grant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(FlagNote, 'change_covflag')
        note = FlagNote.objects.create(title='n')
        people = {
            'live': Principal.objects.create(name='live'),
            'hidden': Principal.objects.create(name='hidden', is_anonymous=True),
            'signed-out': Principal.objects.create(
                name='signed-out', is_authenticated=False,
            ),
            'stopped': Principal.objects.create(name='stopped', is_active=False),
        }
        for person in people.values():
            Grant.objects.create(user=person, note=note, permission=change)
        handle = compiler(
            path='tests.core.coverage-flags', user_model=Principal,
        )
        handle.register(
            trust=Grant, user='user', permission='permission', content='note',
        )
        users = built_catalog(handle).permitted_users(note, change)
        sql = str(users.query)
        self.assertIn('is_anonymous', sql)
        self.assertIn('is_authenticated', sql)
        self.assertEqual(set(users.values_list('name', flat=True)), {'live'})

    def test_non_boolean_and_custom_principal_flags_fail_closed(self):
        class BadNote(models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_badflag_note'

        class TextFlag(models.Model):
            name = models.CharField(max_length=40)
            is_anonymous = models.CharField(max_length=5, default='no')
            is_authenticated = models.BooleanField(default=True)
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_badflag_text'

        class CustomFlag(models.Model):
            name = models.CharField(max_length=40)
            is_active = models.IntegerField(default=1)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_badflag_custom'

            @property
            def is_anonymous(self):
                return False

            is_authenticated = AbstractBaseUser.is_authenticated

        class TextGrant(models.Model):
            user = models.ForeignKey(TextFlag, on_delete=models.CASCADE)
            note = models.ForeignKey(BadNote, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_badflag_text_grant'

        opened = _tables(BadNote, TextFlag, TextGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(BadNote, 'change_covbadflag')
        note = BadNote.objects.create(title='n')
        holder = TextFlag.objects.create(name='holder')
        TextGrant.objects.create(user=holder, note=note, permission=change)
        text = compiler(path='tests.core.coverage-text-flag', user_model=TextFlag)
        text.register(
            trust=TextGrant, user='user', permission='permission', content='note',
        )
        with self.assertRaisesRegex(TrustsConfigurationError, 'BooleanField'):
            list(built_catalog(text).permitted_users(note, change))

        class Counted(models.Model):
            is_active = models.IntegerField(default=1)
            is_anonymous = AbstractBaseUser.is_anonymous
            is_authenticated = AbstractBaseUser.is_authenticated

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_badflag_counted'

        with self.assertRaisesRegex(TrustsConfigurationError, 'stock'):
            assert_persisted_principal(CustomFlag)
        with self.assertRaisesRegex(TrustsConfigurationError, 'BooleanField'):
            assert_persisted_principal(Counted)

    def test_two_candidate_user_models_do_not_mix(self):
        User = get_user_model()

        class MixNote(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_mix_note'

        class Extra(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_mix_extra'

        class UserGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            note = models.ForeignKey(MixNote, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_mix_user_grant'

        class ExtraGrant(models.Model):
            extra = models.ForeignKey(Extra, on_delete=models.CASCADE)
            note = models.ForeignKey(MixNote, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_mix_extra_grant'

        opened = _tables(MixNote, Extra, UserGrant, ExtraGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(MixNote, 'change_covmix')
        note = MixNote.objects.create(title='n')
        handle = compiler(path='tests.core.coverage-mix')
        handle.register(
            trust=UserGrant, user='user', permission='permission', content='note',
        )
        handle.register(
            trust=ExtraGrant, user='extra', permission='permission', content='note',
        )
        with published_class_catalog(HostTrustModelBackend, handle), override_settings(
            AUTHENTICATION_BACKENDS=(
                'tests.kernel_host.backends.HostTrustModelBackend',
            ),
        ):
            with self.assertRaisesRegex(TrustsConfigurationError, 'one registered'):
                list(note.get_permitted_users(change))


class ToFieldIdentityTest(TransactionTestCase):
    """A ``to_field`` parent is compared by the related row's own key."""

    def test_parent_identity_and_along_walk_use_the_code(self):
        User = get_user_model()

        class Item(PermittedUsersMixin, models.Model):
            code = models.CharField(max_length=20, unique=True)
            parent = models.ForeignKey(
                'self', to_field='code', null=True, blank=True,
                on_delete=models.CASCADE, related_name='kids',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_item'

        class ItemGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            item = models.ForeignKey(
                Item, to_field='code', on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_item_grant'

        self.addCleanup(_drop_model, ItemGrant)
        self.addCleanup(_drop_model, Item)
        opened = _tables(Item, ItemGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(Item, 'change_covitem')
        root = Item.objects.create(code='root')
        child = Item.objects.create(code='child', parent=root)
        other = Item.objects.create(code='other')
        alice = User.objects.create_user('cov-item', password='x')
        for item in (child, other):
            ItemGrant.objects.create(user=alice, item=item, permission=change)
        parent_of = compiler(path='tests.core.coverage-to-field')
        parent_of.add_named_filter(
            Item, 'under_root',
            lambda user, permission, obj: obj.parent == root,
        )
        parent_of.register(
            trust=ItemGrant, user='user', permission='permission', content='item',
        )
        walked = compiler(path='tests.core.coverage-to-field-along')
        walked.register(
            trust=ItemGrant, user='user', permission='permission', content='item',
            along=('item__parent', 3),
        )
        code = 'trusts_tests.change_covitem'
        with published_class_catalog(
            HostTrustModelBackend, parent_of,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertTrue(alice.has_perm('%s:under_root' % code, child))
            self.assertFalse(alice.has_perm('%s:under_root' % code, other))
            self.assertFalse(alice.has_perm('%s:under_root' % code, root))
        ItemGrant.objects.all().delete()
        ItemGrant.objects.create(user=alice, item=root, permission=change)
        with published_class_catalog(
            HostTrustModelBackend, walked,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            reached = set(child.get_permitted_users(change).values_list(
                'username', flat=True,
            ))
            self.assertEqual(reached, {'cov-item'})
            self.assertEqual(
                set(other.get_permitted_users(change).values_list(
                    'username', flat=True,
                )),
                set(),
            )
            prepared, extra = bind_once(
                ItemGrant.objects.all(),
                Q(user_id=alice.pk) & Q(permission_id=change.pk),
                user_model=User,
            )
            self.assertEqual(
                set(prepared.filter(extra).values_list('pk', flat=True)),
                set(ItemGrant.objects.filter(
                    user=alice, permission=change,
                ).values_list('pk', flat=True)),
            )
        coded = compiler(path='tests.core.coverage-to-field-code')
        coded.register(
            trust=ItemGrant, user='user', permission='permission', content='item',
            along=(
                lambda row: row.item.parent & (row.item.code == 'child'),
                3,
            ),
        )
        with published_class_catalog(
            HostTrustModelBackend, coded,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertEqual(
                set(child.get_permitted_users(change).values_list(
                    'username', flat=True,
                )),
                {'cov-item'},
            )
            self.assertEqual(
                set(other.get_permitted_users(change).values_list(
                    'username', flat=True,
                )),
                set(),
            )

    def test_an_identity_column_named_ident_still_walks(self):
        User = get_user_model()

        class Box(PermittedUsersMixin, models.Model):
            ident = models.CharField(max_length=20, unique=True)
            parent = models.ForeignKey(
                'self', to_field='ident', null=True, blank=True,
                on_delete=models.CASCADE, related_name='kids',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_box'

        class BoxGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            box = models.ForeignKey(
                Box, to_field='ident', on_delete=models.CASCADE,
            )
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_box_grant'

        self.addCleanup(_drop_model, BoxGrant)
        self.addCleanup(_drop_model, Box)
        opened = _tables(Box, BoxGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(Box, 'change_covbox')
        root = Box.objects.create(ident='root')
        child = Box.objects.create(ident='child', parent=root)
        other = Box.objects.create(ident='other')
        alice = User.objects.create_user('cov-box', password='x')
        BoxGrant.objects.create(user=alice, box=root, permission=change)
        handle = compiler(path='tests.core.coverage-ident')
        handle.register(
            trust=BoxGrant, user='user', permission='permission', content='box',
            along=('box__parent', 3),
        )
        with published_class_catalog(
            HostTrustModelBackend, handle,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertEqual(
                set(child.get_permitted_users(change).values_list(
                    'username', flat=True,
                )),
                {'cov-box'},
            )
            self.assertEqual(
                set(other.get_permitted_users(change).values_list(
                    'username', flat=True,
                )),
                set(),
            )

    def test_a_custom_user_boolean_keeps_the_same_rows(self):
        class FlagUser(models.Model):
            name = models.CharField(max_length=20)
            is_flag = models.BooleanField(default=False)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag_user'

        self.addCleanup(_drop_model, FlagUser)
        opened = _tables(FlagUser)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        yes = FlagUser.objects.create(name='yes', is_flag=True)
        FlagUser.objects.create(name='no', is_flag=False)
        prepared, extra = bind_once(
            FlagUser.objects.filter(is_flag=True), Q(), user_model=FlagUser,
        )
        self.assertEqual(
            set(prepared.filter(extra).values_list('pk', flat=True)),
            {yes.pk},
        )


class NegatedFlagTest(TransactionTestCase):
    """``~`` on a boolean field denies the true rows and renders."""

    def test_a_closed_flag_is_the_only_grant(self):
        User = get_user_model()

        class FlagQuerySet(PermittedQuerySetMixin, models.QuerySet):
            pass

        class Flag(PermittedUsersMixin, models.Model):
            open = models.BooleanField(default=True)
            objects = models.Manager.from_queryset(FlagQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag'

        class FlagGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            flag = models.ForeignKey(Flag, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_flag_grant'

        self.addCleanup(_drop_model, FlagGrant)
        self.addCleanup(_drop_model, Flag)
        opened = _tables(Flag, FlagGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(Flag, 'change_covflag')
        opened_row = Flag.objects.create(open=True)
        closed = Flag.objects.create(open=False)
        alice = User.objects.create_user('cov-flag', password='x')
        for row in (opened_row, closed):
            FlagGrant.objects.create(user=alice, flag=row, permission=change)
        handle = compiler(path='tests.core.coverage-not')
        handle.add_named_filter(Flag, 'shut', lambda user, permission, obj: ~obj.open)
        handle.add_named_filter(Flag, 'open', lambda user, permission, obj: ~~obj.open)
        handle.register(
            trust=FlagGrant, user='user', permission='permission', content='flag',
        )
        code = 'trusts_tests.change_covflag'
        with published_class_catalog(
            HostTrustModelBackend, handle,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertFalse(alice.has_perm('%s:shut' % code, opened_row))
            self.assertTrue(alice.has_perm('%s:shut' % code, closed))
            self.assertTrue(alice.has_perm('%s:open' % code, opened_row))
            self.assertFalse(alice.has_perm('%s:open' % code, closed))
            self.assertEqual(
                set(Flag.objects.permitted(
                    code, alice, conditions=('shut',),
                ).values_list('pk', flat=True)),
                {closed.pk},
            )
        document = render_configured_policy(handle)
        self.assertIn(b'NOT', document)
        conditioned = compiler(path='tests.core.coverage-not-row')
        conditioned.register(
            trust=FlagGrant, user='user', permission='permission',
            content='flag', condition=lambda row: ~row.flag.open,
        )
        with published_class_catalog(
            HostTrustModelBackend, conditioned,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertFalse(alice.has_perm(code, opened_row))
            self.assertTrue(alice.has_perm(code, closed))
        locked = render_configured_policy(conditioned)
        self.assertIn(b'not ', locked)
        from django.contrib.auth.models import Group
        unsaved = Group(name='cov-unsaved')
        ghost = compiler(path='tests.core.coverage-unsaved-member')
        with self.assertRaisesRegex(PermissionConditionError, 'Unsaved'):
            ghost.set_user_condition(
                'ghost', lambda user: user.groups.contains(unsaved),
            )
        self.assertEqual(ghost.records, ())
        group = Group.objects.create(name='cov-real')
        refused = compiler(path='tests.core.coverage-not-member')
        with self.assertRaisesRegex(PermissionConditionError, "'~'"):
            refused.set_user_condition(
                'out', lambda user: ~user.groups.contains(group),
            )
        self.assertEqual(refused.records, ())

class CoverageRouter:
    """Sends every read to the test database."""

    def db_for_read(self, model, **hints):
        return 'default'


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionCodenameMembershipTest(TransactionTestCase):
    """``.contains(permission.codename)`` matches a text primary key."""

    def test_tag_code_matches_the_permission_codename(self):
        User = get_user_model()

        class Tag(models.Model):
            code = models.CharField(max_length=40, primary_key=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_tag'

        class SheetQuerySet(PermittedQuerySetMixin, models.QuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=40)
            tags = models.ManyToManyField(Tag, related_name='sheets')
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_sheet'

        class SheetGrant(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            sheet = models.ForeignKey(Sheet, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'cov_sheet_grant'

        opened = _tables(Tag, Sheet, SheetGrant)
        opened.__enter__()
        self.addCleanup(opened.__exit__, None, None, None)
        change = _permission(Sheet, 'change_covsheet')
        tagged = Sheet.objects.create(title='tagged')
        plain = Sheet.objects.create(title='plain')
        tagged.tags.add(Tag.objects.create(code=change.codename))
        plain.tags.add(Tag.objects.create(code='other'))
        alice = User.objects.create_user('cov-sheet', password='x')
        for sheet in (tagged, plain):
            SheetGrant.objects.create(
                user=alice, sheet=sheet, permission=change,
            )
        handle = compiler(path='tests.core.coverage-codename-member')
        handle.add_named_filter(
            Sheet, 'tagged',
            lambda user, permission, obj: obj.tags.contains(permission.codename),
        )
        handle.add_named_filter(
            Sheet, 'app',
            lambda user, permission, obj: obj.tags.contains(permission.app_label),
        )
        tagged.tags.add(Tag.objects.create(code='trusts_tests'))
        handle.register(
            trust=SheetGrant, user='user', permission='permission',
            content='sheet',
        )
        code = 'trusts_tests.change_covsheet'
        filtered = '%s:tagged' % code
        with published_class_catalog(
            HostTrustModelBackend, handle,
        ), override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
        )):
            self.assertTrue(alice.has_perm(filtered, tagged))
            self.assertFalse(alice.has_perm(filtered, plain))
            self.assertTrue(alice.has_perm('%s:app' % code, tagged))
            self.assertFalse(alice.has_perm('%s:app' % code, plain))
            scoped = set(filter_by_permitted_content(
                Sheet.objects.all(), alice, change, content=tagged,
                conditions=('tagged',),
            ).values_list('pk', flat=True))
            self.assertEqual(scoped, set())
            self.assertEqual(
                set(Sheet.objects.permitted(
                    change, alice, conditions=('app',),
                ).values_list('pk', flat=True)),
                {tagged.pk},
            )
            catalog = built_catalog(handle)
            for _model, tree in catalog.prepared_conditions.values():
                compiled = compile_to_q(tree, Sheet, alice, change, User)
                self.assertEqual(
                    set(Sheet.objects.filter(compiled).values_list(
                        'pk', flat=True,
                    )),
                    {tagged.pk},
                )
            document = render_configured_policy(handle)
            self.assertIn(b'$permission.codename', document)
            self.assertIn(b'$permission.app_label', document)
            self.assertEqual(
                set(tagged.get_permitted_users('%s:app' % code).values_list(
                    'username', flat=True,
                )),
                {'cov-sheet'},
            )
            self.assertIn(tagged.pk, set(Sheet.objects.permitted(
                code, alice, conditions=('tagged',),
            ).values_list('pk', flat=True)))
            self.assertNotIn(plain.pk, set(Sheet.objects.permitted(
                change, alice, conditions=('tagged',),
            ).values_list('pk', flat=True)))
            self.assertEqual(
                set(tagged.get_permitted_users(filtered).values_list(
                    'username', flat=True,
                )),
                {'cov-sheet'},
            )
            self.assertEqual(
                set(plain.get_permitted_users(filtered).values_list(
                    'username', flat=True,
                )),
                set(),
            )
            tagged._state.db = None
            with override_settings(DATABASE_ROUTERS=(
                'tests.core.test_coverage_behavior.CoverageRouter',
            )):
                self.assertEqual(
                    set(tagged.get_permitted_users(filtered).values_list(
                        'username', flat=True,
                    )),
                    {'cov-sheet'},
                )
