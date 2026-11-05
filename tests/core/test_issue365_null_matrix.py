"""Observation probe for issue #365. Not a definition of correctness.

The pinned matrix is what revision 186e632 returned on SQLite, PostgreSQL,
and MySQL. It is not a behavior to preserve, and this module is not a
patch. ``.permitted()`` is one column. A projection that cannot receive
the expression is ``n/a-*`` or ``base-*``, not a fail. A form the grammar
or a compiler rejects is ``unsupported``.

Run from the repository root:

    python3 -m tests.runtests tests.core.test_issue365_null_matrix

PostgreSQL 16 and MySQL 8.4 use ``tests.along_db_settings`` so ``auth``
is migrated before any foreign key to ``auth_user``. SQLite uses the
kernel settings.

    DJANGO_SETTINGS_MODULE=tests.along_db_settings \\
    TRUSTS_TEST_DATABASE=postgresql TRUSTS_PG_USER=trusts \\
    TRUSTS_PG_PASSWORD=trusts TRUSTS_PG_NAME=trusts \\
    python3 -m tests.runtests tests.core.test_issue365_null_matrix

    DJANGO_SETTINGS_MODULE=tests.along_db_settings \\
    TRUSTS_TEST_DATABASE=mysql TRUSTS_MYSQL_USER=root \\
    TRUSTS_MYSQL_PASSWORD=root TRUSTS_MYSQL_NAME=trusts \\
    python3 -m tests.runtests tests.core.test_issue365_null_matrix
"""
import inspect
import json
import os
import subprocess
import sys
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldError, PermissionDenied
from django.db import connection, transaction
from django.db.utils import DataError, IntegrityError, OperationalError, ProgrammingError
from django.http import Http404, HttpRequest
from django.test import TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext, isolate_apps

from tests.support import built_catalog, compiler, published_class_catalog
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import authorization_required, filter_by_permitted_content
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)
from trusts.plan.grammar import invoke


_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_EXPECTED = os.path.join(_HERE, 'issue365_expected.json')
_GAP_EXPECTED = os.path.join(_HERE, 'issue365_gap_expected.json')
_REGISTER_ERRORS = (
    TrustsConfigurationError, PermissionConditionError, TypeError, ValueError,
)
_DB_ERRORS = (IntegrityError, OperationalError, ProgrammingError, DataError)
_QUERY_ERRORS = _DB_ERRORS + (
    FieldError, TrustsConfigurationError, PermissionConditionError,
)


class _ProbeBackend(TrustModelBackendMixin, ModelBackend):
    pass


@contextmanager
def _listed(handle):
    with published_class_catalog(_ProbeBackend, handle):
        with override_settings(
            AUTHENTICATION_BACKENDS=(
                'tests.core.test_issue365_null_matrix._ProbeBackend',
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


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _yn(flag):
    return 'hold' if flag else 'fail'


def _base(flag):
    return 'base-hold' if flag else 'base-fail'


def _na(flag):
    return 'n/a-but-hold' if flag else 'n/a-empty'


def _one_line(exc):
    text = '%s: %s' % (type(exc).__name__, exc)
    return ' '.join(text.split())


def _revision():
    return subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=_ROOT, text=True,
    ).strip()


def _owners():
    """Line ranges of the 37 functions that decide a comparison."""
    import trusts.decorators as decorators
    import trusts.plan.predicates as predicates
    import trusts.plan.recursions as recursions
    import trusts.plan.relations as relations
    import trusts.plan.standards as standards
    import trusts.plan.users as users
    import trusts.plan.via as via
    import trusts.plan.walk as walk
    import trusts.plan.writers as writers

    found = {
        'trusts.plan.writers._walk_model_path': writers._walk_model_path,
        'trusts.plan.writers.values_match': writers.values_match,
        'trusts.plan.writers.columns_q': writers.columns_q,
        'trusts.plan.writers.column_q': writers.column_q,
        'trusts.plan.writers.boolean_holds': writers.boolean_holds,
        'trusts.plan.writers.boolean_q': writers.boolean_q,
        'trusts.plan.writers.negate_q': writers.negate_q,
        'trusts.plan.writers._compile_contains': writers._compile_contains,
        'trusts.plan.writers._collection_contains': writers._collection_contains,
        'trusts.plan.via._walk_node': via._walk_node,
        'trusts.plan.via._local_field': via._local_field,
        'trusts.plan.via._user_expr': via._user_expr,
        'trusts.plan.via._field_sql': via._field_sql,
        'trusts.plan.via._compare_sql': via._compare_sql,
        'trusts.plan.via._contains_sql': via._contains_sql,
        'trusts.plan.via._object_value': via._object_value,
        'trusts.plan.via._permission_predicate': via._permission_predicate,
        'trusts.plan.via._permission_join_sql': via._permission_join_sql,
        'trusts.plan.via._read_instance': via._read_instance,
        'trusts.plan.walk._stop_predicate': walk._stop_predicate,
        'trusts.plan.walk._edge_predicate': walk._edge_predicate,
        'trusts.plan.walk._render_reach_sql': walk._render_reach_sql,
        'trusts.plan.walk._render_keyed_reach_sql': walk._render_keyed_reach_sql,
        'trusts.plan.walk._sponsor_walk_seed': walk._sponsor_walk_seed,
        'trusts.plan.walk._delegation_walk_seed': walk._delegation_walk_seed,
        'trusts.plan.recursions.GrantReach.__init__': recursions.GrantReach.__init__,
        'trusts.plan.recursions._PrefixInForwardWalk.__init__': (
            recursions._PrefixInForwardWalk.__init__
        ),
        'trusts.plan.users._contains_outcome': users._contains_outcome,
        'trusts.plan.users._negated_outcome': users._negated_outcome,
        'trusts.plan.users._user_object_q': users._user_object_q,
        'trusts.plan.users._trusts_eligibility_q': users._trusts_eligibility_q,
        'trusts.plan.standards.principal_identity_lookups': (
            standards.principal_identity_lookups
        ),
        'trusts.plan.standards._compile_user_contains': (
            standards._compile_user_contains
        ),
        'trusts.plan.predicates._PredicateCompiler._eq': (
            predicates._PredicateCompiler._eq
        ),
        'trusts.plan.predicates._PredicateCompiler._contains': (
            predicates._PredicateCompiler._contains
        ),
        'trusts.plan.relations._user_identity_denied': relations._user_identity_denied,
        'trusts.decorators._authorize_candidate': decorators._authorize_candidate,
    }
    ranges = {}
    for name, fn in found.items():
        lines, start = inspect.getsourcelines(fn)
        ranges[name] = [start, start + len(lines) - 1]
    return ranges


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
    if accessor and accessor != '+' and hasattr(model, accessor):
        delattr(model, accessor)


def _drop_column(model, column):
    quote = connection.ops.quote_name
    table = model._meta.db_table
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


def _add_column(test, model, name, field):
    model.add_to_class(name, field)
    stored = model._meta.get_field(name)

    def detach():
        try:
            try:
                _drop_column(model, stored.column)
            except Exception:
                with connection.schema_editor() as editor:
                    editor.remove_field(model, stored)
        finally:
            _forget_field(model, stored)

    try:
        with connection.schema_editor() as editor:
            editor.add_field(model, stored)
    except Exception:
        _forget_field(model, stored)
        raise
    test.addCleanup(detach)
    return stored


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _shape(sqls):
    text = '\n'.join(sqls).upper()
    return {
        'left': 'LEFT OUTER JOIN' in text or 'LEFT JOIN' in text,
        'inner': 'INNER JOIN' in text,
        'is_null': 'IS NULL' in text,
        'is_not_null': 'IS NOT NULL' in text,
        'is_true': ' IS TRUE' in text or 'IS TRUE' in text,
        'is_not_true': 'IS NOT TRUE' in text,
        'not_exists': 'NOT EXISTS' in text,
        'coalesce': 'COALESCE' in text,
        'sql': '\n'.join(sqls)[:2000],
    }


def _unsupported(error):
    return {'kind': 'unsupported', 'error': error}


def _publish_reverse(test, model):
    """Show a reverse one-to-one to the user model's field resolver.

    ``isolate_apps`` registers the new model on a temporary registry.
    The installed user was built on the process registry, and
    ``get_field`` only sees reverse relations from that registry.
    Publishing the model there is test setup. Cleanup removes it.
    """
    registry = get_user_model()._meta.apps
    registry.register_model(model._meta.app_label, model)
    registry.clear_cache()

    def detach():
        bucket = registry.all_models.get(model._meta.app_label)
        if bucket is not None:
            bucket.pop(model._meta.model_name, None)
        registry.clear_cache()
        user_model = get_user_model()
        if 'probe_plaque' in user_model.__dict__:
            del user_model.__dict__['probe_plaque']

    test.addCleanup(detach)


def _try_invoke(fn, roots):
    try:
        invoke(fn, roots)
    except Exception as exc:
        return _one_line(exc)
    return 'built'


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NullSemanticsProbe(TransactionTestCase):
    """Record #365 cells. The pin is an observation, not an oracle."""

    def test_observed_matrix(self):
        payload = self._collect()
        blob = json.dumps(payload, indent=2, sort_keys=True)
        if not os.path.exists(_EXPECTED):
            tmp = '/tmp/issue365_observed.json'
            with open(tmp, 'w', encoding='utf-8') as handle:
                handle.write(blob)
            self.fail('pinned matrix missing; wrote %s' % tmp)
        with open(_EXPECTED, encoding='utf-8') as handle:
            expected = json.load(handle)
        # The pin names the production revision the answers were measured
        # against. Later test commits sit on that tree; HEAD is not the pin.
        self.assertEqual(expected['revision'], _PRODUCTION)
        diff = subprocess.check_output(
            ['git', 'diff', '--stat', _PRODUCTION, '--', 'trusts'],
            cwd=_ROOT, text=True,
        )
        self.assertEqual(diff, '')
        self.assertEqual(payload['owners'], expected['owners'])
        want = dict(expected['cases'])
        want.update(expected.get('vendor_cases', {}).get(connection.vendor, {}))
        if payload['cases'] != want:
            with open('/tmp/issue365_last.json', 'w', encoding='utf-8') as handle:
                json.dump(payload['cases'], handle)
        self.assertEqual(payload['cases'], want)

    def _collect(self):
        world = self._build()
        cases = {}
        sql = {}
        meta_notes = []
        self._user_cases(world, cases, sql)
        self._filter_cases(world, cases, sql)
        self._group_cases(world, cases, sql)
        self._delegation_cases(world, cases, sql)
        self._reset_cases(world, cases, meta_notes)
        self._identity_cases(world, cases, meta_notes)
        cases.update(self._unsupported_cases(world))
        vendor = connection.vendor
        with connection.cursor() as cursor:
            cursor.execute('SELECT VERSION()' if vendor != 'sqlite' else 'SELECT sqlite_version()')
            db_version = cursor.fetchone()[0]
        return {
            'revision': _revision(),
            'owners': _owners(),
            'cases': cases,
            'meta': {
                'vendor': vendor,
                'database_version': db_version,
                'django': __import__('django').get_version(),
                'sql': sql,
                'notes': meta_notes,
            },
        }

    def _build(self):
        User = get_user_model()

        from django.db import models

        class Dept(models.Model):
            region = models.CharField(max_length=20, null=True)
            flag = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_dept'

        class Tag(models.Model):
            label = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_tag'

        class Cabinet(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_cabinet'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            cabinet = models.ForeignKey(
                Cabinet, related_name='sheets', on_delete=models.CASCADE,
            )
            region = models.CharField(max_length=20, null=True)
            other = models.CharField(max_length=20, null=True)
            flag = models.BooleanField(null=True)
            dept = models.ForeignKey(
                Dept, null=True, related_name='sheets', on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField(Tag, related_name='sheets')
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_sheet'

        class Policy(models.Model):
            cabinet = models.ForeignKey(
                Cabinet, related_name='policies', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_policy'

        class Edge(models.Model):
            parent = models.ForeignKey(
                Cabinet, related_name='child_links', on_delete=models.CASCADE,
            )
            child = models.ForeignKey(
                Cabinet, related_name='parent_links', on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_edge'

        class Grant(models.Model):
            user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_grant'

        class GroupGrant(models.Model):
            group = models.ForeignKey(Group, on_delete=models.CASCADE)
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_group_grant'

        class Link(models.Model):
            delegate = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            sponsor = models.ForeignKey(
                User, related_name='+', on_delete=models.CASCADE,
            )
            cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE)
            region = models.CharField(max_length=20, null=True)
            other = models.CharField(max_length=20, null=True)
            flag = models.BooleanField(null=True)
            dept = models.ForeignKey(
                Dept, null=True, related_name='links', on_delete=models.CASCADE,
            )
            tags = models.ManyToManyField(Tag, related_name='links')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365_link'

        models_ = (
            Dept, Tag, Cabinet, Sheet, Policy, Edge, Grant, GroupGrant, Link,
        )
        cm = _tables(*models_)
        cm.__enter__()
        self.addCleanup(lambda: cm.__exit__(None, None, None))
        _add_column(
            self, User, 'probe_nick',
            models.CharField(max_length=40, null=True),
        )
        _add_column(
            self, User, 'probe_other',
            models.CharField(max_length=40, null=True),
        )
        _add_column(
            self, User, 'probe_flag',
            models.BooleanField(null=True),
        )
        _add_column(
            self, User, 'probe_manager',
            models.ForeignKey(
                'self', null=True, blank=True, related_name='probe_reports',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            ),
        )
        _add_column(
            self, User, 'probe_dept',
            models.ForeignKey(
                Dept, null=True, blank=True, related_name='+',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            ),
        )

        east = Dept.objects.create(region='east', flag=True)
        null_dept = Dept.objects.create(region=None, flag=None)
        t1 = Tag.objects.create(label='t1')
        t2 = Tag.objects.create(label='t2')
        perm = _permission(Sheet, 'change_probe365_sheet')
        code = 'trusts_tests.change_probe365_sheet'
        g1 = Group.objects.create(name='p365-g1')
        g2 = Group.objects.create(name='p365-g2')
        gprobe = Group.objects.create(name='p365-gprobe')
        gprobe.permissions.add(perm)

        def sheet(title, region, other, flag, dept, tags):
            cabinet = Cabinet.objects.create(title=title, reset_inheritance=None)
            row = Sheet.objects.create(
                title=title, cabinet=cabinet, region=region, other=other,
                flag=flag, dept=dept,
            )
            if tags:
                row.tags.add(*tags)
            return cabinet, row

        cabinets = {}
        sheets = {}
        for title, region, other, flag, dept, tags in (
            ('sv', 'east', 'east', True, east, (t1, t2)),
            ('sn', None, None, None, null_dept, ()),
            ('sm', 'west', 'east', False, None, (t1,)),
            ('skm', None, None, None, None, ()),
            ('skn', None, None, None, null_dept, ()),
        ):
            cabinet, row = sheet(title, region, other, flag, dept, tags)
            cabinets[title] = cabinet
            sheets[title] = row
        # The OR fixture needs the literal name the other branch tests.
        sheets['skm'].title = 'keep'
        sheets['skm'].save(update_fields=['title'])
        sheets['skn'].title = 'keep'
        sheets['skn'].save(update_fields=['title'])

        people = {}

        def person(label, nick, other, flag, dept, groups=(), manager=None):
            user = User.objects.create_user('p365-%s' % label, password='x')
            user.probe_label = label
            user.probe_nick = nick
            user.probe_other = other
            user.probe_flag = flag
            user.probe_dept = dept
            user.probe_manager = manager
            user.save()
            if groups:
                user.groups.add(*groups)
            people[label] = user
            return user

        person('vv', 'east', 'east', True, east, (g1, g2, gprobe))
        person('nn', None, None, None, null_dept, (gprobe,))
        person('mm', 'west', 'east', False, None, (g1,))
        person('orm', 'keep', 'keep', False, None)
        person('orn', 'keep', None, None, null_dept)
        boss_nick = person('boss_nick', None, 'east', True, east)
        person('child_nick', 'east', 'east', True, east, manager=boss_nick)
        boss_flag = person('boss_flag', 'east', 'east', True, east)
        person('child_flag', 'east', 'east', False, east, manager=boss_flag)
        person('coded', perm.codename, perm.codename, True, east)
        sponsor = person('sponsor', 'east', 'east', True, east)
        person('sT', 'east', 'east', True, east)
        person('sF', 'east', 'east', False, east)
        person('sN', 'east', 'east', None, east)
        for label in ('dV', 'dN', 'dM', 'dST', 'dSF', 'dSN', 'dW'):
            person(label, 'east', 'east', True, east)
        person('wP', 'east', 'east', True, east)
        person('wA', 'east', 'east', True, east)
        person('wB', 'east', 'east', True, east)

        matrix_labels = (
            'vv', 'nn', 'mm', 'orm', 'orn', 'child_nick', 'boss_nick',
            'child_flag', 'boss_flag', 'coded',
        )
        for label in matrix_labels:
            for title in ('sv', 'sn', 'sm', 'skm', 'skn'):
                Grant.objects.create(
                    user=people[label], cabinet=cabinets[title], permission=perm,
                )
        Grant.objects.create(
            user=sponsor, cabinet=cabinets['sv'], permission=perm,
        )
        for label in ('sT', 'sF', 'sN'):
            Grant.objects.create(
                user=people[label], cabinet=cabinets['sv'], permission=perm,
            )
        GroupGrant.objects.create(group=gprobe, cabinet=cabinets['sv'])

        def link(delegate, sponsor_user, cabinet, region, other, flag, dept, tags=()):
            row = Link.objects.create(
                delegate=delegate, sponsor=sponsor_user, cabinet=cabinet,
                region=region, other=other, flag=flag, dept=dept,
            )
            if tags:
                row.tags.add(*tags)
            return row

        link(people['dV'], sponsor, cabinets['sv'], 'east', 'east', True, east, (t1, t2))
        link(people['dN'], sponsor, cabinets['sv'], None, None, None, null_dept)
        link(people['dM'], sponsor, cabinets['sv'], 'west', 'east', False, None, (t1,))
        link(people['dST'], people['sT'], cabinets['sv'], None, None, None, None)
        link(people['dSF'], people['sF'], cabinets['sv'], None, None, None, None)
        link(people['dSN'], people['sN'], cabinets['sv'], None, None, None, None)

        reset = {}
        specs = (
            ('P', None, None),
            ('A', 'P', True),
            ('B', 'A', False),
            ('C', 'B', None),
            ('D', 'C', None),
        )
        for title, parent, flag in specs:
            reset[title] = Cabinet.objects.create(
                title=title,
                parent=None if parent is None else reset[parent],
                reset_inheritance=flag,
            )
            Sheet.objects.create(
                title=title, cabinet=reset[title], region=None, other=None,
                flag=None, dept=None,
            )
        Policy.objects.create(cabinet=reset['B'], reset_inheritance=None)
        Policy.objects.create(cabinet=reset['C'], reset_inheritance=False)
        Policy.objects.create(cabinet=reset['D'], reset_inheritance=True)
        Edge.objects.create(
            parent=reset['P'], child=reset['A'], reset_inheritance=True,
        )
        Edge.objects.create(
            parent=reset['A'], child=reset['B'], reset_inheritance=None,
        )
        Edge.objects.create(
            parent=reset['B'], child=reset['C'], reset_inheritance=False,
        )
        for label, title in (('wP', 'P'), ('wA', 'A'), ('wB', 'B')):
            Grant.objects.create(
                user=people[label], cabinet=reset[title], permission=perm,
            )
        link(people['dW'], people['wP'], reset['P'], None, None, None, None)

        world = {
            'User': User,
            'Sheet': Sheet,
            'Cabinet': Cabinet,
            'Grant': Grant,
            'GroupGrant': GroupGrant,
            'Link': Link,
            'people': people,
            'sheets': sheets,
            'cabinets': cabinets,
            'reset': reset,
            'perm': perm,
            'code': code,
            'east': east,
            'null_dept': null_dept,
            't1': t1,
            't2': t2,
            'g1': g1,
        }
        return world

    def _open(self, name, *, user_expr=None, on='*', filt=None, filt_model=None,
              trust=None, via=None, along=None, delegation=False, group=False):
        safe = name.replace('/', '-')
        handle = compiler(path='tests.core.issue365.%s' % safe)
        if user_expr is not None:
            handle.set_user_condition('probe', user_expr, on=on)
        if filt is not None:
            handle.add_named_filter(filt_model, 'probe', filt)
        kwargs = {}
        if via is not None:
            kwargs['via'] = via
        if along is not None:
            kwargs['along'] = along
        if delegation:
            handle.register(
                trust=trust, delegate='delegate', sponsor='sponsor',
                content='cabinet__sheets', **kwargs,
            )
        elif group:
            handle.register(
                trust=trust, user='group__user', group='group',
                content='cabinet__sheets', **kwargs,
            )
        else:
            handle.register(
                trust=trust, user='user', permission='permission',
                content='cabinet__sheets', **kwargs,
            )
        return handle

    def _open_maybe(self, *args, **kwargs):
        try:
            return self._open(*args, **kwargs), None
        except _REGISTER_ERRORS as exc:
            return None, _one_line(exc)

    def _guard_views(self, world):
        code = world['code']
        sheet_model = world['Sheet']

        @authorization_required(sheet_model, code)
        def plain(request, pk):
            return 'ok'

        @authorization_required(sheet_model, code, ('probe',))
        def filtered(request, pk):
            return 'ok'

        return plain, filtered

    def _measure(self, world, handle, users, sheets, *, filtered, group,
                 capture_labels=()):
        catalog = built_catalog(handle)
        code = world['code']
        perm = world['perm']
        conds = ('probe',) if filtered else ()
        perm_code = '%s:probe' % code if filtered else code
        reverse_arg = perm_code if filtered else perm
        plain_view, filtered_view = self._guard_views(world)
        view = filtered_view if filtered else plain_view
        subjects = {}
        sql = {}

        def _ids(fn):
            try:
                return set(fn()), None
            except _QUERY_ERRORS as exc:
                return set(), 'error:%s' % type(exc).__name__

        with _listed(handle):
            reverse = {}
            reverse_error = {}
            for sheet in sheets:
                try:
                    reverse[sheet.pk] = set(
                        sheet.get_permitted_users(reverse_arg).values_list(
                            'pk', flat=True,
                        )
                    )
                    reverse_error[sheet.pk] = None
                except _QUERY_ERRORS as exc:
                    reverse[sheet.pk] = set()
                    reverse_error[sheet.pk] = 'error:%s' % type(exc).__name__
            for user in users:
                capture = user.probe_label in capture_labels
                if capture:
                    with CaptureQueriesContext(connection) as captured:
                        permitted_ids, permitted_error = _ids(lambda: (
                            world['Sheet'].objects.permitted(
                                code, user, conditions=conds,
                            ).values_list('pk', flat=True)
                        ))
                    sql[user.probe_label] = _shape(
                        [item['sql'] for item in captured.captured_queries]
                    )
                else:
                    permitted_ids, permitted_error = _ids(lambda: (
                        world['Sheet'].objects.permitted(
                            code, user, conditions=conds,
                        ).values_list('pk', flat=True)
                    ))
                authorized_ids, authorized_error = _ids(lambda: (
                    world['Sheet'].objects.authorized(
                        user, perm,
                    ).values_list('pk', flat=True)
                ))
                prefix_ids, prefix_error = _ids(lambda: (
                    filter_by_permitted_content(
                        world['Cabinet'].objects.all(), user, perm,
                        content=world['Sheet'], conditions=conds,
                    ).values_list('pk', flat=True)
                ))
                for sheet in sheets:
                    try:
                        has = _yn(user.has_perm(perm_code, sheet))
                    except _QUERY_ERRORS as exc:
                        has = 'error:%s' % type(exc).__name__
                    if reverse_error[sheet.pk]:
                        reached = reverse_error[sheet.pk]
                    else:
                        reached = _yn(user.pk in reverse[sheet.pk])
                    try:
                        complete = code in user.get_all_permissions(sheet)
                        complete_error = None
                    except _QUERY_ERRORS as exc:
                        complete, complete_error = False, type(exc).__name__
                    try:
                        grouped = code in user.get_group_permissions(sheet)
                        grouped_error = None
                    except _QUERY_ERRORS as exc:
                        grouped, grouped_error = False, type(exc).__name__
                    try:
                        common = catalog.permissions_for(user, sheet)
                        if common in ((), None):
                            common_holds = False
                        else:
                            common_holds = perm.pk in set(
                                common.values_list('pk', flat=True)
                            )
                        common_error = None
                    except _QUERY_ERRORS as exc:
                        common_holds, common_error = False, type(exc).__name__
                    try:
                        view(_request(user), pk=sheet.pk)
                        guarded = 'hold'
                    except PermissionDenied:
                        guarded = 'fail'
                    except Http404:
                        guarded = 'missing'
                    except _QUERY_ERRORS as exc:
                        guarded = 'error:%s' % type(exc).__name__
                    if permitted_error:
                        permitted_cell = permitted_error
                    else:
                        permitted_cell = _yn(sheet.pk in permitted_ids)
                    if authorized_error:
                        auth_cell = authorized_error
                    elif filtered:
                        auth_cell = _base(sheet.pk in authorized_ids)
                    else:
                        auth_cell = _yn(sheet.pk in authorized_ids)
                    if complete_error:
                        all_cell = 'error:%s' % complete_error
                    elif filtered:
                        all_cell = _base(complete)
                    else:
                        all_cell = _yn(complete)
                    if common_error:
                        common_cell = 'error:%s' % common_error
                    elif filtered:
                        common_cell = _base(common_holds)
                    else:
                        common_cell = _yn(common_holds)
                    if grouped_error:
                        group_cell = 'error:%s' % grouped_error
                    elif group:
                        group_cell = _yn(grouped)
                    else:
                        group_cell = _na(grouped)
                    if prefix_error:
                        prefix_cell = prefix_error
                    else:
                        prefix_cell = _yn(sheet.cabinet_id in prefix_ids)
                    key = '%s/%s' % (user.probe_label, sheet.cabinet.title)
                    subjects[key] = {
                        'has_perm': has,
                        'permitted': permitted_cell,
                        'authorized': auth_cell,
                        'get_permitted_users': reached,
                        'get_all_permissions': all_cell,
                        'common_permissions': common_cell,
                        'get_group_permissions': group_cell,
                        'filter_by_permitted_content': prefix_cell,
                        'authorization_required': guarded,
                    }
        return {'kind': 'ran', 'subjects': subjects}, sql

    def _put(self, cases, sql, name, handle, error, world, users, sheets,
             **measure):
        if handle is None:
            cases[name] = _unsupported(error)
            print(name, 'unsupported', file=sys.stderr)
            return
        print(name, file=sys.stderr)
        case, captured = self._measure(
            world, handle, users, sheets, **measure,
        )
        cases[name] = case
        if captured:
            sql[name] = captured

    def _labels(self, world, labels):
        return [world['people'][label] for label in labels]

    def _sheet_list(self, world, titles):
        return [world['sheets'][title] for title in titles]

    def _user_cases(self, world, cases, sql):
        labels = (
            'vv', 'nn', 'mm', 'orm', 'orn', 'child_nick', 'boss_nick',
            'child_flag', 'boss_flag',
        )
        users = self._labels(world, labels)
        sheets = self._sheet_list(world, ('sv', 'sn', 'sm'))
        exprs = (
            ('nick-eq-east', lambda user: user.probe_nick == 'east'),
            ('nick-ne-east', lambda user: user.probe_nick != 'east'),
            ('nick-eq-none', lambda user: user.probe_nick == None),  # noqa: E711
            ('nick-ne-none', lambda user: user.probe_nick != None),  # noqa: E711
            ('nick-eq-other', lambda user: user.probe_nick == user.probe_other),
            ('nick-ne-other', lambda user: user.probe_nick != user.probe_other),
            ('flag-bare', lambda user: user.probe_flag),
            ('flag-not', lambda user: ~user.probe_flag),
            ('flag-eq-true', lambda user: user.probe_flag == True),  # noqa: E712
            ('flag-eq-false', lambda user: user.probe_flag == False),  # noqa: E712
            ('flag-eq-none', lambda user: user.probe_flag == None),  # noqa: E711
            ('flag-ne-true', lambda user: user.probe_flag != True),  # noqa: E712
            ('flag-ne-false', lambda user: user.probe_flag != False),  # noqa: E712
            ('dept-eq-east', lambda user: user.probe_dept.region == 'east'),
            ('dept-ne-east', lambda user: user.probe_dept.region != 'east'),
            ('dept-eq-none', lambda user: user.probe_dept.region == None),  # noqa: E711
            ('dept-flag-bare', lambda user: user.probe_dept.flag),
            ('dept-flag-not', lambda user: ~user.probe_dept.flag),
            (
                'or-missing-dept',
                lambda user: (
                    (user.probe_dept.region == 'east')
                    | (user.probe_nick == 'keep')
                ),
            ),
            (
                'and-missing-dept',
                lambda user: (
                    (user.probe_dept.region == 'east')
                    & (user.probe_nick == 'keep')
                ),
            ),
            (
                'not-and-flag',
                lambda user: ~(user.probe_flag & user.probe_flag),
            ),
            (
                'not-or-not-flag',
                lambda user: ~user.probe_flag | ~user.probe_flag,
            ),
            (
                'guard-ne-true',
                lambda user: (
                    (user.probe_flag != None) & (user.probe_flag != True)  # noqa: E711, E712
                ),
            ),
            ('groups-contains', lambda user: user.groups.contains(world['g1'])),
            ('groups-contains-none', lambda user: user.groups.contains(None)),
        )
        for label, expr in exprs:
            for via, suffix in ((False, 'direct'), (True, 'via')):
                name = 'user-%s/%s' % (suffix, label)
                kwargs = {'user_expr': expr, 'trust': world['Grant']}
                if via:
                    kwargs['via'] = ('user__probe_manager', 4)
                handle, error = self._open_maybe(name, **kwargs)
                capture = ()
                if label in ('or-missing-dept', 'dept-ne-east', 'nick-ne-east'):
                    capture = ('orm', 'nn', 'mm')
                self._put(
                    cases, sql, name, handle, error, world, users, sheets,
                    filtered=False, group=False, capture_labels=capture,
                )

    def _filter_cases(self, world, cases, sql):
        t1, t2 = world['t1'], world['t2']
        users = self._labels(world, ('vv', 'nn', 'mm', 'orm', 'orn', 'coded'))
        sheets = self._sheet_list(world, ('sv', 'sn', 'sm', 'skm', 'skn'))
        exprs = (
            ('region-eq-east', lambda user, permission, content: content.region == 'east'),
            ('region-ne-east', lambda user, permission, content: content.region != 'east'),
            ('region-eq-none', lambda user, permission, content: content.region == None),  # noqa: E711
            ('region-ne-none', lambda user, permission, content: content.region != None),  # noqa: E711
            ('region-eq-other', lambda user, permission, content: content.region == content.other),
            ('region-ne-other', lambda user, permission, content: content.region != content.other),
            ('flag-bare', lambda user, permission, content: content.flag),
            ('flag-not', lambda user, permission, content: ~content.flag),
            ('flag-eq-true', lambda user, permission, content: content.flag == True),  # noqa: E712
            ('flag-eq-false', lambda user, permission, content: content.flag == False),  # noqa: E712
            ('flag-eq-none', lambda user, permission, content: content.flag == None),  # noqa: E711
            ('flag-ne-true', lambda user, permission, content: content.flag != True),  # noqa: E712
            ('flag-ne-false', lambda user, permission, content: content.flag != False),  # noqa: E712
            ('dept-eq-east', lambda user, permission, content: content.dept.region == 'east'),
            ('dept-ne-east', lambda user, permission, content: content.dept.region != 'east'),
            ('dept-eq-none', lambda user, permission, content: content.dept.region == None),  # noqa: E711
            ('dept-flag-bare', lambda user, permission, content: content.dept.flag),
            ('dept-flag-not', lambda user, permission, content: ~content.dept.flag),
            (
                'or-missing-dept',
                lambda user, permission, content: (
                    (content.dept.region == 'east') | (content.title == 'keep')
                ),
            ),
            (
                'and-missing-dept',
                lambda user, permission, content: (
                    (content.dept.region == 'east') & (content.title == 'keep')
                ),
            ),
            (
                'not-and-flag',
                lambda user, permission, content: ~(content.flag & content.flag),
            ),
            (
                'not-or-not-flag',
                lambda user, permission, content: ~content.flag | ~content.flag,
            ),
            ('tags-t1', lambda user, permission, content: content.tags.contains(t1.pk)),
            ('tags-t2', lambda user, permission, content: content.tags.contains(t2.pk)),
            ('tags-none', lambda user, permission, content: content.tags.contains(None)),
            (
                'tags-both',
                lambda user, permission, content: (
                    content.tags.contains(t1.pk) & content.tags.contains(t2.pk)
                ),
            ),
            (
                'cross-eq',
                lambda user, permission, content: user.probe_nick == content.region,
            ),
            (
                'cross-ne',
                lambda user, permission, content: user.probe_nick != content.region,
            ),
            (
                'cross-dept-eq',
                lambda user, permission, content: (
                    user.probe_dept.region == content.dept.region
                ),
            ),
            (
                'cross-dept-ne',
                lambda user, permission, content: (
                    user.probe_dept.region != content.dept.region
                ),
            ),
            (
                'perm-code',
                lambda user, permission, content: user.probe_nick == permission.codename,
            ),
            (
                'user-groups',
                lambda user, permission, content: user.groups.contains(world['g1']),
            ),
        )
        for label, expr in exprs:
            for via, suffix in ((False, 'direct'), (True, 'via')):
                name = 'filter-%s/%s' % (suffix, label)
                kwargs = {
                    'filt': expr,
                    'filt_model': world['Sheet'],
                    'trust': world['Grant'],
                }
                if via:
                    kwargs['via'] = ('user__probe_manager', 4)
                handle, error = self._open_maybe(name.replace('/', '-'), **kwargs)
                capture = ()
                if label in (
                    'or-missing-dept', 'dept-eq-east', 'dept-ne-east',
                    'region-ne-east', 'cross-dept-eq', 'cross-ne',
                ):
                    capture = ('vv', 'orm')
                self._put(
                    cases, sql, name, handle, error, world, users, sheets,
                    filtered=True, group=False, capture_labels=capture,
                )

    def _group_cases(self, world, cases, sql):
        users = self._labels(world, ('vv', 'nn', 'mm'))
        sheets = self._sheet_list(world, ('sv',))
        exprs = (
            ('nick-ne-east', lambda user: user.probe_nick != 'east'),
            ('nick-eq-none', lambda user: user.probe_nick == None),  # noqa: E711
            ('flag-not', lambda user: ~user.probe_flag),
            ('flag-ne-true', lambda user: user.probe_flag != True),  # noqa: E712
            ('flag-eq-false', lambda user: user.probe_flag == False),  # noqa: E712
        )
        for label, expr in exprs:
            name = 'group/%s' % label
            handle, error = self._open_maybe(
                name, user_expr=expr, trust=world['GroupGrant'], group=True,
            )
            self._put(
                cases, sql, name, handle, error, world, users, sheets,
                filtered=False, group=True,
            )

    def _delegation_cases(self, world, cases, sql):
        row_users = self._labels(world, ('dV', 'dN', 'dM', 'sponsor'))
        sponsor_users = self._labels(
            world, ('dST', 'dSF', 'dSN', 'sT', 'sF', 'sN'),
        )
        sheets = self._sheet_list(world, ('sv',))
        row_exprs = (
            ('region-eq-east', lambda row: row.region == 'east'),
            ('region-ne-east', lambda row: row.region != 'east'),
            ('region-eq-none', lambda row: row.region == None),  # noqa: E711
            ('region-eq-other', lambda row: row.region == row.other),
            ('region-ne-other', lambda row: row.region != row.other),
            ('flag-bare', lambda row: row.flag),
            ('flag-not', lambda row: ~row.flag),
            ('flag-eq-false', lambda row: row.flag == False),  # noqa: E712
            ('flag-ne-true', lambda row: row.flag != True),  # noqa: E712
            ('dept-eq-east', lambda row: row.dept.region == 'east'),
            ('dept-ne-east', lambda row: row.dept.region != 'east'),
            ('dept-eq-none', lambda row: row.dept.region == None),  # noqa: E711
            ('dept-flag-not', lambda row: ~row.dept.flag),
            ('tags-t1', lambda row: row.tags.contains(world['t1'].pk)),
            ('tags-none', lambda row: row.tags.contains(None)),
            (
                'or-missing-dept',
                lambda row: (row.dept.region == 'east') | (row.region == 'west'),
            ),
        )
        # The ordinary grant lets the sponsor reach sv. The row condition
        # filters the delegate's link. Both registrations share one catalog.
        for label, expr in row_exprs:
            name = 'deleg-row/%s' % label
            try:
                handle = compiler(path='tests.core.issue365.link-%s' % label)
                handle.register(
                    trust=world['Grant'], user='user', permission='permission',
                    content='cabinet__sheets',
                )
                handle.register(
                    trust=world['Link'], delegate='delegate', sponsor='sponsor',
                    content='cabinet__sheets', condition=expr,
                )
                error = None
            except _REGISTER_ERRORS as exc:
                handle, error = None, _one_line(exc)
            self._put(
                cases, sql, name, handle, error, world, row_users, sheets,
                filtered=False, group=False,
            )
        for via, suffix in ((False, 'direct'), (True, 'via')):
            name = 'deleg-sponsor-%s/flag-ne-true' % suffix
            kwargs = {
                'user_expr': lambda user: user.probe_flag != True,  # noqa: E712
                'on': 'sponsor',
                'trust': world['Grant'],
            }
            try:
                handle = compiler(path='tests.core.issue365.%s' % name)
                handle.set_user_condition(
                    'probe', lambda user: user.probe_flag != True, on='sponsor',  # noqa: E712
                )
                handle.register(
                    trust=world['Grant'], user='user', permission='permission',
                    content='cabinet__sheets',
                )
                deleg_kwargs = {}
                if via:
                    deleg_kwargs['via'] = ('sponsor__probe_manager', 4)
                handle.register(
                    trust=world['Link'], delegate='delegate', sponsor='sponsor',
                    content='cabinet__sheets', **deleg_kwargs,
                )
                error = None
            except _REGISTER_ERRORS as exc:
                handle, error = None, _one_line(exc)
            self._put(
                cases, sql, name, handle, error, world, sponsor_users, sheets,
                filtered=False, group=False,
            )

    def _reach(self, world, handle, users):
        catalog_error = None
        found = {}
        try:
            built_catalog(handle)
        except _REGISTER_ERRORS as exc:
            return _unsupported(_one_line(exc))
        with _listed(handle):
            for user in users:
                try:
                    titles = set(
                        world['Sheet'].objects.permitted(
                            world['code'], user,
                        ).values_list('title', flat=True)
                    )
                except _QUERY_ERRORS as exc:
                    found[user.probe_label] = 'error:%s' % type(exc).__name__
                    continue
                found[user.probe_label] = sorted(titles)
        if catalog_error:
            return _unsupported(catalog_error)
        return {'kind': 'reach', 'actors': found}

    def _reset_cases(self, world, cases, notes):
        actors = self._labels(world, ('wP', 'wA', 'wB', 'dW'))
        specs = (
            ('reset/node', ('cabinet__parent', 4, 'reset_inheritance'), False),
            ('reset/children', ('cabinet__children', 4, 'reset_inheritance'), False),
            ('reset/any', ('cabinet__parent', 4, 'policies__reset_inheritance'), False),
            (
                'reset/edge',
                ('cabinet__parent_links__parent', 4, 'parent_links__reset_inheritance'),
                False,
            ),
            ('reset/plain-parent', ('cabinet__parent', 4), False),
        )
        for name, along, _deleg in specs:
            try:
                handle = compiler(path='tests.core.issue365.%s' % name)
                handle.register(
                    trust=world['Grant'], user='user', permission='permission',
                    content='cabinet__sheets', along=along,
                )
            except _REGISTER_ERRORS as exc:
                cases[name] = _unsupported(_one_line(exc))
                continue
            cases[name] = self._reach(world, handle, actors[:3])
        try:
            handle = compiler(path='tests.core.issue365.reset-deleg')
            handle.register(
                trust=world['Grant'], user='user', permission='permission',
                content='cabinet__sheets',
                along=('cabinet__parent', 4, 'reset_inheritance'),
            )
            handle.register(
                trust=world['Link'], delegate='delegate', sponsor='sponsor',
                content='cabinet__sheets',
                along=('cabinet__parent', 4, 'reset_inheritance'),
            )
            cases['reset/deleg-along'] = self._reach(world, handle, actors)
        except _REGISTER_ERRORS as exc:
            cases['reset/deleg-along'] = _unsupported(_one_line(exc))
        for bad, value in (
            ('reset/not-a-field', ('cabinet__parent', 4, 'missing_flag')),
            ('reset/condition', ('cabinet__parent', 4, 'flag != True')),
            ('reset/empty', ('cabinet__parent', 4, '')),
        ):
            try:
                handle = compiler(path='tests.core.issue365.%s' % bad)
                handle.register(
                    trust=world['Grant'], user='user', permission='permission',
                    content='cabinet__sheets', along=value,
                )
                cases[bad] = {'kind': 'ran', 'subjects': {}}
            except _REGISTER_ERRORS as exc:
                cases[bad] = _unsupported(_one_line(exc))
        notes.append(
            'Reset reach is the set of sheet titles permitted() returned. '
            'The grant sites are wP on P, wA on A, wB on B. dW is a delegate '
            'of wP whose link is on P.'
        )

    def _identity_cases(self, world, cases, notes):
        from django.db import models

        User = world['User']
        _add_column(
            self, User, 'is_anonymous', models.BooleanField(null=True),
        )
        _add_column(
            self, User, 'is_authenticated', models.BooleanField(null=True),
        )
        perm = world['perm']
        cabinet = world['cabinets']['sv']
        sheet = world['sheets']['sv']
        specs = (
            ('ia_null', None, True),
            ('ia_true', True, True),
            ('ia_false', False, True),
            ('auth_null', False, None),
            ('auth_false', False, False),
            ('both_ok', False, True),
        )
        people = []
        for label, anonymous, authenticated in specs:
            user = User.objects.create_user('p365-%s' % label, password='x')
            User.objects.filter(pk=user.pk).update(
                is_anonymous=anonymous, is_authenticated=authenticated,
            )
            user.refresh_from_db()
            user.probe_label = label
            world['Grant'].objects.create(
                user=user, cabinet=cabinet, permission=perm,
            )
            people.append(user)
        handle, error = self._open_maybe(
            'identity-plain', trust=world['Grant'],
        )
        if handle is None:
            cases['identity/columns'] = _unsupported(error)
        else:
            case, _sql = self._measure(
                world, handle, people, [sheet], filtered=False, group=False,
            )
            cases['identity/columns'] = case
        active = User.objects.create_user('p365-active-null', password='x')
        active.probe_label = 'active_null'
        world['Grant'].objects.create(
            user=active, cabinet=cabinet, permission=perm,
        )
        try:
            with transaction.atomic():
                User.objects.filter(pk=active.pk).update(is_active=None)
            active.refresh_from_db()
            stored = active.is_active
            notes.append('is_active NULL update stored %r' % (stored,))
            if stored is None and handle is not None:
                case, _sql = self._measure(
                    world, handle, [active], [sheet],
                    filtered=False, group=False,
                )
                cases['identity/active-null'] = case
            else:
                cases['identity/active-null'] = _unsupported(
                    'update did not store NULL (got %r)' % (stored,)
                )
        except _DB_ERRORS as exc:
            cases['identity/active-null'] = _unsupported(
                'stock is_active column rejects NULL'
            )
            notes.append('is_active NULL rejected: %s' % _one_line(exc))

    def _unsupported_cases(self, world):
        found = {}
        attempts = (
            ('unsupported/ordered', lambda user: user.probe_nick < 'm', ('user',)),
            (
                'unsupported/tilde-comparison',
                lambda user: ~(user.probe_nick == 'east'),
                ('user',),
            ),
            (
                'unsupported/tilde-or',
                lambda user: ~(user.probe_flag | user.probe_flag),
                ('user',),
            ),
            (
                'unsupported/tilde-contains',
                lambda user: ~(user.groups.contains(world['g1'])),
                ('user',),
            ),
            (
                'unsupported/tag-field',
                lambda user, permission, content: content.tags.label == 't1',
                ('user', 'permission', 'object'),
            ),
            (
                'unsupported/coalesce-absent',
                None,
                (),
            ),
        )
        for name, fn, roots in attempts:
            if fn is None:
                try:
                    __import__('trusts.functions')
                    found[name] = {'kind': 'ran', 'subjects': {}}
                except ImportError as exc:
                    found[name] = _unsupported(_one_line(exc))
                continue
            if name == 'unsupported/tag-field':
                try:
                    handle = compiler(path='tests.core.issue365.tag-field')
                    handle.add_named_filter(world['Sheet'], 'probe', fn)
                    handle.register(
                        trust=world['Grant'], user='user',
                        permission='permission', content='cabinet__sheets',
                    )
                    found[name] = {'kind': 'ran', 'subjects': {}}
                except _REGISTER_ERRORS as exc:
                    found[name] = _unsupported(_one_line(exc))
                continue
            found[name] = _unsupported(_try_invoke(fn, roots))
        return found


_PRODUCTION = '186e632b0284f453eb7b6f49aabf2bf5c31bed67'


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class GapProbeTest(TransactionTestCase):
    """Measurements the #366 pin did not already record.

    Production code is unchanged. ``dept == None`` is the relation.
    ``dept.region == None`` is the leaf. A later hop is ``dept.unit.code``.
    ``code`` is not null. ``probe_plaque`` is a reverse one-to-one made
    visible on the installed user for this test only.
    """

    def test_gap_measurements(self):
        world = self._world()
        found = {}
        shapes = {}
        queries = (
            ('rel-none', lambda user: user.probe_dept == None,  # noqa: E711
             ('absent', 'nullreg', 'nounit', 'withunit')),
            ('leaf-none', lambda user: user.probe_dept.region == None,  # noqa: E711
             ('absent', 'nullreg', 'nounit', 'withunit')),
            ('unit-none', lambda user: user.probe_dept.unit == None,  # noqa: E711
             ('absent', 'nullreg', 'nounit', 'withunit')),
            ('hop-none', lambda user: user.probe_dept.unit.code == None,  # noqa: E711
             ('absent', 'nullreg', 'nounit', 'withunit')),
            ('hop-ne', lambda user: user.probe_dept.unit.code != 'east',
             ('absent', 'nullreg', 'nounit', 'withunit')),
            ('leaf-ne-lit', lambda user: user.probe_dept.region != 'east',
             ('absent', 'nullreg', 'west', 'withunit')),
            ('leaf-ne-field',
             lambda user: user.probe_dept.region != user.probe_east,
             ('absent', 'nullreg', 'west', 'withunit')),
            ('leaf-ne-rev',
             lambda user: user.probe_east != user.probe_dept.region,
             ('absent', 'nullreg', 'west', 'withunit')),
            ('or-path-right',
             lambda user: (
                 (user.probe_dept.region == user.probe_east)
                 | (user.probe_east == 'east')
             ),
             ('absent', 'nullreg', 'west')),
            ('or-path-left',
             lambda user: (
                 (user.probe_east == 'east')
                 | (user.probe_dept.region == user.probe_east)
             ),
             ('absent', 'nullreg', 'west')),
            ('or-false-right',
             lambda user: (
                 (user.probe_dept.region == user.probe_east)
                 | (user.probe_east == 'nope')
             ),
             ('absent', 'nullreg')),
            ('bare-banned', lambda user: user.is_banned,
             ('open_true', 'open_false', 'banned')),
            ('not-banned', lambda user: ~user.is_banned,
             ('open_true', 'open_false', 'banned')),
            ('notnot-banned', lambda user: ~~user.is_banned,
             ('open_true', 'open_false', 'banned')),
            ('bare-clear', lambda user: user.is_not_banned,
             ('open_true', 'open_false', 'banned')),
            ('not-clear', lambda user: ~user.is_not_banned,
             ('open_true', 'open_false', 'banned')),
            ('notnot-clear', lambda user: ~~user.is_not_banned,
             ('open_true', 'open_false', 'banned')),
            ('mixed', lambda user: ~(user.is_banned & user.gate),
             ('open_true', 'open_false', 'banned')),
            ('mixed-clear', lambda user: ~(user.is_not_banned & user.gate),
             ('open_true', 'open_false', 'banned')),
            ('plaque-none', lambda user: user.probe_plaque == None,  # noqa: E711
             ('noplaque', 'nulllabel', 'eastlabel')),
            ('plaque-leaf-none',
             lambda user: user.probe_plaque.label == None,  # noqa: E711
             ('noplaque', 'nulllabel', 'eastlabel')),
            ('plaque-leaf-ne',
             lambda user: user.probe_plaque.label != 'east',
             ('noplaque', 'nulllabel', 'eastlabel')),
        )
        capture = {
            'rel-none', 'leaf-none', 'unit-none', 'hop-none', 'hop-ne',
            'or-path-right', 'or-path-left', 'plaque-none',
        }
        for name, expr, labels in queries:
            for via in (False, True):
                key = ('via/' + name) if via else name
                case, shape = self._run(
                    world, key, expr, labels, via=via,
                    capture=name in capture and not via,
                )
                found[key] = case
                if shape:
                    shapes[key] = shape
        with open(_GAP_EXPECTED, encoding='utf-8') as handle:
            expected = json.load(handle)
        self.assertEqual(expected.get('production'), _PRODUCTION)
        want = dict(expected['cases'])
        want.update(expected.get('vendor_cases', {}).get(connection.vendor, {}))
        if found != want:
            with open('/tmp/issue365_gap_found.json', 'w', encoding='utf-8') as handle:
                json.dump(
                    {'vendor': connection.vendor, 'cases': found, 'shapes': shapes},
                    handle, indent=2, sort_keys=True,
                )
        self.assertEqual(found, want)
        diff = subprocess.check_output(
            ['git', 'diff', '--stat', _PRODUCTION, '--', 'trusts'],
            cwd=_ROOT, text=True,
        )
        self.assertEqual(diff, '')

    def _world(self):
        from django.db import models

        User = get_user_model()

        class Unit(models.Model):
            code = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365g_unit'

        class Dept(models.Model):
            region = models.CharField(max_length=20, null=True)
            unit = models.ForeignKey(
                Unit, null=True, related_name='depts', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365g_dept'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365g_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE,
            )
            sheet = models.ForeignKey(Sheet, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365g_grant'

        class Plaque(models.Model):
            user = models.OneToOneField(
                User, related_name='probe_plaque', on_delete=models.CASCADE,
            )
            label = models.CharField(max_length=20, null=True)

            class Meta:
                # Installed on the SQLite settings and on along_db_settings.
                # trusts_tests is not installed on the latter, so a reverse
                # relation registered only there is invisible to User.
                app_label = 'trusts_kernel_host'
                db_table = 'p365g_plaque'

        _publish_reverse(self, Plaque)
        cm = _tables(Unit, Dept, Sheet, Grant, Plaque)
        cm.__enter__()
        self.addCleanup(lambda: cm.__exit__(None, None, None))
        for name, field in (
            ('probe_east', models.CharField(max_length=20, null=True)),
            ('probe_dept', models.ForeignKey(
                Dept, null=True, blank=True, related_name='+',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            )),
            ('probe_manager', models.ForeignKey(
                'self', null=True, blank=True, related_name='gap_reports',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            )),
            ('is_banned', models.BooleanField(null=True)),
            ('is_not_banned', models.BooleanField(null=True)),
            ('gate', models.BooleanField(null=True)),
        ):
            _add_column(self, User, name, field)

        held = Unit.objects.create(code='east')
        other = Unit.objects.create(code='west')
        null_region = Dept.objects.create(region=None, unit=None)
        east_nounit = Dept.objects.create(region='east', unit=None)
        east_unit = Dept.objects.create(region='east', unit=held)
        west = Dept.objects.create(region='west', unit=other)
        perm = _permission(Sheet, 'change_probe365_gap')
        code = 'trusts_tests.change_probe365_gap'
        sheet = Sheet.objects.create(title='gap')
        people = {}

        def person(label, dept, banned=None, clear=None, gate=True):
            user = User.objects.create_user('p365g-%s' % label, password='x')
            user.probe_label = label
            user.probe_east = 'east'
            user.probe_dept = dept
            user.is_banned = banned
            user.is_not_banned = clear
            user.gate = gate
            user.save()
            Grant.objects.create(user=user, permission=perm, sheet=sheet)
            people[label] = user
            return user

        person('absent', None)
        person('nullreg', null_region)
        person('nounit', east_nounit)
        person('withunit', east_unit)
        person('west', west)
        person('open_false', None, gate=False)
        person('banned', None, banned=True, clear=False, gate=True)
        person('noplaque', None)
        nulllabel = person('nulllabel', None)
        eastlabel = person('eastlabel', None)
        # open_true is "absent": both flags NULL, gate true.
        people['open_true'] = people['absent']
        Plaque.objects.create(user=nulllabel, label=None)
        Plaque.objects.create(user=eastlabel, label='east')
        return {
            'User': User,
            'Sheet': Sheet,
            'Grant': Grant,
            'people': people,
            'perm': perm,
            'code': code,
            'sheet': sheet,
            'production': '186e632b0284f453eb7b6f49aabf2bf5c31bed67',
        }

    def _run(self, world, name, expr, labels, *, via, capture):
        handle = compiler(path='tests.core.issue365.gap.%s' % name.replace('/', '-'))
        try:
            handle.set_user_condition('probe', expr)
            kwargs = {}
            if via:
                kwargs['via'] = ('user__probe_manager', 4)
            handle.register(
                trust=world['Grant'], user='user', permission='permission',
                content='sheet', **kwargs,
            )
        except _REGISTER_ERRORS as exc:
            return _unsupported(_one_line(exc)), None
        users = []
        seen = set()
        for label in labels:
            user = world['people'][label]
            if user.pk in seen:
                continue
            seen.add(user.pk)
            users.append(user)
        return self._tri(world, handle, users, labels, capture=capture)

    def _tri(self, world, handle, users, labels, *, capture):
        code = world['code']
        perm = world['perm']
        sheet = world['sheet']
        subjects = {}
        shape = None
        with _listed(handle):
            try:
                reached = set(
                    sheet.get_permitted_users(perm).values_list('pk', flat=True)
                )
                reverse_error = None
            except _QUERY_ERRORS as exc:
                reached = set()
                reverse_error = 'error:%s' % type(exc).__name__
            for label in labels:
                user = world['people'][label]
                if capture and label == labels[0]:
                    with CaptureQueriesContext(connection) as captured:
                        try:
                            permitted_ids = set(
                                world['Sheet'].objects.permitted(
                                    code, user,
                                ).values_list('pk', flat=True)
                            )
                            permitted_error = None
                        except _QUERY_ERRORS as exc:
                            permitted_ids = set()
                            permitted_error = 'error:%s' % type(exc).__name__
                    shape = _shape(
                        [item['sql'] for item in captured.captured_queries]
                    )
                    shape.pop('sql', None)
                else:
                    try:
                        permitted_ids = set(
                            world['Sheet'].objects.permitted(
                                code, user,
                            ).values_list('pk', flat=True)
                        )
                        permitted_error = None
                    except _QUERY_ERRORS as exc:
                        permitted_ids = set()
                        permitted_error = 'error:%s' % type(exc).__name__
                try:
                    has = _yn(user.has_perm(code, sheet))
                except _QUERY_ERRORS as exc:
                    has = 'error:%s' % type(exc).__name__
                if reverse_error:
                    reverse = reverse_error
                else:
                    reverse = _yn(user.pk in reached)
                if permitted_error:
                    permitted = permitted_error
                else:
                    permitted = _yn(sheet.pk in permitted_ids)
                subjects[label] = {
                    'has_perm': has,
                    'permitted': permitted,
                    'get_permitted_users': reverse,
                }
        return {'kind': 'ran', 'subjects': subjects}, shape
