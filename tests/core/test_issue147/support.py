"""Shared fixtures for the #147 lockfile audit slices.

These helpers are test-only. They are not part of the product contract.
"""

import hashlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connections, models
from django.db.models import Manager

from trusts.core import BackendHandle, PlanQueryCompiler, Ref, TrustsRegistry
from trusts.decorators import authorization_required
from trusts.policy_lock import (
    ALONG_SUPPORTED,
    COMPILER_VERSION,
    SCHEMA_VERSION,
    SQLITE_JSON1_RCTE_PROFILE,
    build_policy_manifest,
    fingerprint_registration,
    manifest_to_json_data,
)
from trusts.query import AuthorizedManagerMixin, AuthorizedQuerySet

REPO_ROOT = Path(__file__).resolve().parents[3]

_FINGERPRINT = __import__('re').compile(r'^sha256:[0-9a-f]{64}$')

_REGISTRATION_KEYS = (
    'fingerprint', 'label', 'kind', 'root',
    'user', 'user_model', 'user_target',
    'permission', 'permission_model', 'permission_target',
    'content', 'content_model', 'content_target',
    'condition', 'along',
)


def _policy_models():
    User = get_user_model()

    class Org(models.Model):
        name = models.CharField(max_length=40)
        code = models.CharField(max_length=40, unique=True)

        class Meta:
            app_label = 'trusts_tests'

    class Doc(models.Model):
        title = models.CharField(max_length=40)
        confidential = models.BooleanField(default=False)
        rank = models.IntegerField(default=0)
        organization = models.ForeignKey(
            Org, related_name='docs', on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Grant(models.Model):
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        document = models.ForeignKey(Doc, on_delete=models.CASCADE)
        team_org = models.ForeignKey(
            Org, related_name='team_grants', on_delete=models.CASCADE,
        )
        repo_org = models.ForeignKey(
            Org, related_name='repo_grants', on_delete=models.CASCADE,
        )
        alt_org = models.ForeignKey(
            Org, related_name='alt_grants', on_delete=models.CASCADE,
        )
        coded_org = models.ForeignKey(
            Org, to_field='code', related_name='coded_grants',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Node(models.Model):
        parent = models.ForeignKey(
            'self', null=True, related_name='children',
            on_delete=models.CASCADE,
        )

        class Meta:
            app_label = 'trusts_tests'

    class Item(models.Model):
        node = models.ForeignKey(
            Node, related_name='items', on_delete=models.CASCADE,
        )
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    class NodeGrant(models.Model):
        node = models.ForeignKey(Node, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Org, Doc, Grant, Node, Item, NodeGrant


def _direct(registry, grant, content='document'):
    root = Ref(grant)
    return registry.register(
        content=getattr(root, content),
        user=root.user,
        permission=root.permission,
    )


def _handle(registry, path, compiler=None):
    registry.freeze()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler() if compiler is None else compiler,
    )


_owner_seq = 0


@contextmanager
def _installed_owner(path, family='relationship', label=None):
    """Install one strict implementation owner for a synthetic backend path."""
    global _owner_seq
    from django.apps import apps as django_apps

    import tests as tests_module
    from trusts.apps import TrustsImplementationConfig

    _owner_seq += 1
    label = label or ('policy_own_%s' % _owner_seq)
    if label in django_apps.app_configs:
        raise AssertionError('app label %r is already installed' % label)

    class Owner(TrustsImplementationConfig):
        pass

    Owner.label = label
    Owner.trusts_backend_paths = (path,)
    Owner._authorization_family = family
    owner = Owner('tests.%s' % label, tests_module)
    owner.apps = django_apps
    django_apps.app_configs[label] = owner
    try:
        yield owner
    finally:
        django_apps.app_configs.pop(label, None)


@contextmanager
def _owned(*handles):
    with ExitStack() as stack:
        seen = set()
        for handle in handles:
            if handle.path in seen:
                continue
            seen.add(handle.path)
            stack.enter_context(_installed_owner(handle.path))
        yield


def _data(handles, **kwargs):
    with _owned(*handles):
        return manifest_to_json_data(build_policy_manifest(handles, **kwargs))


def _minimal_registration_payload():
    return {
        'kind': 'any_path',
        'root': 'app.Grant',
        'user': ['user'],
        'user_model': 'auth.User',
        'user_target': 'id',
        'permission': ['permission'],
        'permission_model': 'auth.Permission',
        'permission_target': 'id',
        'content': ['document'],
        'content_model': 'app.Doc',
        'content_target': 'id',
        'condition': None,
        'along': None,
    }


def _minimal_along():
    return {
        'bound': 3,
        'shape': 'S',
        'walk_path': ['node'],
        'walk_model': 'app.Node',
        'walk_ident': 'id',
        'suffix_path': ['items'],
        'ident_family': 'integer',
        'parent_attname': 'parent_id',
        'edge_model': None,
        'edge_parent_attname': None,
        'edge_child_attname': None,
        'rewrite_attname': None,
    }


def _semantic_digest(data):
    text = json.dumps(
        data, ensure_ascii=False, indent=2, separators=(',', ': '),
        sort_keys=False,
    )
    if not text.endswith('\n'):
        text += '\n'
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _payload(registration):
    return {
        key: registration[key]
        for key in _REGISTRATION_KEYS
        if key not in ('fingerprint', 'label')
    }


@contextmanager
def _forbid_sql():
    """Fail if snapshot construction opens a cursor or probes Along."""
    connection = connections['default']
    with patch.object(
        connection, 'cursor', side_effect=AssertionError('cursor'),
    ), patch.object(
        connection, 'ensure_connection', side_effect=AssertionError('connect'),
    ), patch(
        'trusts.core.probe_along_capabilities',
        side_effect=AssertionError('probed'),
    ):
        yield


@contextmanager
def _engine(engine, **extra):
    connection = connections['default']
    saved = connection.settings_dict
    try:
        replaced = dict(saved)
        replaced['ENGINE'] = engine
        replaced.update(extra)
        connection.settings_dict = replaced
        yield connection
    finally:
        connection.settings_dict = saved



def _sha(text='ab'):
    return 'sha256:' + (text * 32)


def _lock_document(expr=None):
    """Minimal semantic document. ``expr`` adds one named filter."""
    payload = _minimal_registration_payload()
    registration = {
        'fingerprint': fingerprint_registration(payload),
        'label': 'app.Grant:document',
    }
    registration.update(payload)
    named = []
    if expr is not None:
        named.append({
            'model': 'app.Doc',
            'code': 'ranked',
            'fingerprint': _sha(),
            'expr': expr,
        })
    return {
        'schema_version': SCHEMA_VERSION,
        'compiler_version': COMPILER_VERSION,
        'handles': [{
            'path': 'tests.policy.reader',
            'family': 'relationship',
            'compiler': 'trusts.core.PlanQueryCompiler',
            'renderer': {
                'alias': 'default',
                'engine': 'django.db.backends.sqlite3',
                'profile': SQLITE_JSON1_RCTE_PROFILE,
                'profile_version': 1,
                'along': ALONG_SUPPORTED,
            },
            'registrations': [registration],
            'named_filters': named,
        }],
    }


def _eq_expr(path, const):
    return {
        'op': 'eq',
        'left': {'ref': 'object', 'path': [path]},
        'right': {'const': const},
    }


_SAFE_INT = 2**53 - 1
_OUT_INT = 2**53


def _stamp_registration(row):
    payload = _payload(row)
    row['fingerprint'] = fingerprint_registration(payload)
    return row


class _RuntimeManager(AuthorizedManagerMixin, Manager):
    """Manager surface that must gate before building a queryset."""

    def get_queryset(self):
        raise AssertionError('queryset built before the policy gate')


def _active_owner():
    """Installed implementation for this process.

    Kernel settings own ``HostTrustModelBackend``. The Zero pair owns
    ``trusts.zero.backends.TrustModelBackend``. Neither path is hard-coded.
    """
    from tests.apps import live_config

    return live_config()


def _active_backend():
    from django.utils.module_loading import import_string

    owner = _active_owner()
    handles = owner.configured_handles()
    if not handles:
        raise AssertionError(
            '%s has no configured backend in this environment.'
            % type(owner).__name__
        )
    return import_string(handles[0].path)()


def _same_type_compiler(compiler):
    """New compiler object of the installed type. Not the same instance."""
    if isinstance(compiler, type):
        return compiler()
    return type(compiler)()


def _candidate_queryset():
    """Authorized queryset for a model installed in both environments."""
    return AuthorizedQuerySet(get_user_model())


def _authorization_view():
    """Guard whose model is installed under kernel settings and the pair."""
    model = get_user_model()
    permission = '%s.change_%s' % (model._meta.app_label, model._meta.model_name)

    @authorization_required(model, permission)
    def view(request, **kwargs):
        raise AssertionError('authorization_required view body ran')

    return view


_ISOLATION_CHILD = """\
import json
import os

import django
django.setup()

from django.conf import settings
from django.db import connections
from trusts.policy_lock import (
    ensure_policy_lockfile_verified,
    generate_policy_lockfile,
    _policy_lock_verification_state,
)

sql = {'n': 0}


def wrapper(execute, sql_text, params, many, context):
    sql['n'] += 1
    return execute(sql_text, params, many, context)


case = os.environ['C4B_CASE']
lock = os.environ.get('C4B_LOCK') or None
base = os.environ.get('C4B_BASE') or None
before = _policy_lock_verification_state()
error = None
connection = connections['default']
with connection.execute_wrapper(wrapper):
    try:
        if case == 'generate':
            generate_policy_lockfile(override=lock)
        elif case == 'verify-explicit':
            settings.TRUSTS_POLICY_LOCKFILE = lock
            ensure_policy_lockfile_verified()
        elif case == 'verify-conventional':
            settings.TRUSTS_POLICY_LOCKFILE = None
            settings.BASE_DIR = base
            ensure_policy_lockfile_verified()
        else:
            raise RuntimeError('unknown case %r' % (case,))
    except Exception as exc:
        error = '%s: %s' % (type(exc).__name__, exc)
after = _policy_lock_verification_state()
print(json.dumps({
    'before': before,
    'after': after,
    'error': error,
    'sql': sql['n'],
}))
"""


def _fresh_lock_process(case, *, lock=None, base=None):
    """Run one lockfile action in a new interpreter.

    The child uses this process's settings module and import path, so
    kernel-only and Zero-pair runs stay on the installed owner. It does
    not receive this process's verification memory.

    ``override_settings`` hides ``settings.SETTINGS_MODULE``. The
    process environment still names the installed settings module
    (kernel ``tests.settings`` or the Zero pair module).
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if isinstance(value, str)
    }
    if not env.get('DJANGO_SETTINGS_MODULE'):
        raise AssertionError('DJANGO_SETTINGS_MODULE is not set')
    env['PYTHONPATH'] = os.pathsep.join(
        os.fspath(entry)
        for entry in sys.path
        if isinstance(entry, (str, os.PathLike))
    )
    env['C4B_CASE'] = case
    env['C4B_LOCK'] = '' if lock is None else str(lock)
    env['C4B_BASE'] = '' if base is None else str(base)
    root = REPO_ROOT
    proc = subprocess.run(
        [sys.executable, '-c', _ISOLATION_CHILD],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
        encoding='utf-8',
        check=False,
    )
    detail = proc.stdout + '\n' + proc.stderr
    if proc.returncode != 0:
        raise AssertionError(detail)
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise AssertionError(detail) from exc


def _registry_surface(handle):
    """Identity of the frozen registry contents, not a semantic copy."""
    registry = handle.registry
    filters = tuple(
        (id(model), code, id(record))
        for model, code, record in registry.iter_permission_conditions()
    )
    return (
        id(registry),
        registry.frozen,
        tuple(id(record) for record in registry.records),
        filters,
    )
