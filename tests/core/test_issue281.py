"""Lockfile settings and optional register() labels (#281)."""

import os
import subprocess
import sys
from pathlib import Path

import yaml
from django.conf import global_settings
from django.test import SimpleTestCase, override_settings

from tests.core.test_issue147.test_sql_export import _document_handle
from tests.core.test_register_time import _grant, _probe, _recorder
from tests.myapp.models import DocumentDelegation, DocumentGrant
from tests.support import compiler, render_configured_policy
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import render_policy_sql_bytes
from trusts.plan.rewrites import trusts_bind_once


ROOT = Path(__file__).resolve().parents[2]

_CUSTOM_USER_SOURCE = """\
from django.conf import settings
settings.configure(
    SECRET_KEY='custom-user-settings',
    USE_TZ=True,
    DEFAULT_AUTO_FIELD='django.db.models.AutoField',
    AUTH_USER_MODEL='custom_user.User',
    INSTALLED_APPS=(
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'tests.custom_user.apps.CustomUserConfig',
    ),
    AUTHENTICATION_BACKENDS=(
        'django.contrib.auth.backends.ModelBackend',
    ),
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    },
)
import django
django.setup()
import yaml
from trusts.inspect.snapshot import render_policy_sql_bytes
document = yaml.safe_load(render_policy_sql_bytes())
recorded = document['settings']
assert recorded['AUTH_USER_MODEL'] == 'custom_user.User', recorded
assert recorded['TRUSTS_SQL_BIND_ONCE'] is True, recorded
assert recorded['AUTHENTICATION_BACKENDS'] == [
    'django.contrib.auth.backends.ModelBackend',
], recorded
assert list(document)[:4] == [
    'schema_version', 'database', 'settings', 'backends',
], list(document)
print('custom-user-settings')
"""


def _trust_row(handle):
    document = yaml.safe_load(render_configured_policy(handle))
    return document['backends'][0]['contents'][0]['trusts'][0]


def _settings_block(handle):
    document = yaml.safe_load(render_configured_policy(handle))
    return document['settings']


def _grant_handle(path, **labels):
    handle = compiler()
    handle.path = path
    handle.register(
        trust=DocumentGrant,
        user='user',
        permission='permission',
        content='document',
        **labels,
    )
    return handle


class PolicySettingsBlockTest(SimpleTestCase):

    def test_records_resolved_settings_beside_database(self):
        document = yaml.safe_load(render_configured_policy(_document_handle()))
        self.assertEqual(
            list(document)[:4],
            ['schema_version', 'database', 'settings', 'backends'],
        )
        recorded = document['settings']
        self.assertEqual(
            list(recorded),
            [
                'TRUSTS_SQL_BIND_ONCE',
                'AUTH_USER_MODEL',
                'AUTHENTICATION_BACKENDS',
            ],
        )
        self.assertIs(recorded['TRUSTS_SQL_BIND_ONCE'], trusts_bind_once())
        self.assertIs(recorded['TRUSTS_SQL_BIND_ONCE'], True)
        self.assertEqual(recorded['AUTH_USER_MODEL'], 'auth.User')
        self.assertEqual(recorded['AUTH_USER_MODEL'], global_settings.AUTH_USER_MODEL)
        self.assertNotIn('USE_TZ', recorded)
        self.assertNotIn('BASE_DIR', recorded)
        self.assertNotIn('DATABASES', recorded)
        self.assertNotIn('TRUSTS_POLICY_DATABASE', recorded)
        self.assertNotIn('TRUSTS_POLICY_LOCKFILE', recorded)
        self.assertNotIn('TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', recorded)

    def test_explicit_defaults_match_omitted_settings(self):
        omitted = _settings_block(_document_handle())
        with override_settings(
            TRUSTS_SQL_BIND_ONCE=True,
            AUTH_USER_MODEL='auth.User',
        ):
            explicit = _settings_block(_document_handle())
        self.assertEqual(explicit, omitted)
        self.assertIs(explicit['TRUSTS_SQL_BIND_ONCE'], True)
        self.assertEqual(explicit['AUTH_USER_MODEL'], 'auth.User')

    def test_bind_once_false_is_recorded_and_changes_sql(self):
        enabled = render_configured_policy(_document_handle())
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            disabled = render_configured_policy(_document_handle())
        enabled_doc = yaml.safe_load(enabled)
        disabled_doc = yaml.safe_load(disabled)
        self.assertIs(enabled_doc['settings']['TRUSTS_SQL_BIND_ONCE'], True)
        self.assertIs(disabled_doc['settings']['TRUSTS_SQL_BIND_ONCE'], False)
        enabled_sql = enabled_doc['backends'][0]['contents'][0]['permitted']['sql']
        disabled_sql = disabled_doc['backends'][0]['contents'][0]['permitted']['sql']
        self.assertIn('trusts_bind', enabled_sql)
        self.assertNotIn('trusts_bind', disabled_sql)
        self.assertNotEqual(enabled, disabled)

    def test_authentication_backends_keep_settings_order(self):
        paths = (
            'tests.myapp.backends.DocumentBackend',
            'tests.kernel_host.backends.HostTrustModelBackend',
        )
        with override_settings(AUTHENTICATION_BACKENDS=paths):
            document = yaml.safe_load(render_policy_sql_bytes())
        self.assertEqual(
            document['settings']['AUTHENTICATION_BACKENDS'],
            list(paths),
        )
        listed = [row['path'] for row in document['backends']]
        self.assertEqual(listed, sorted(listed))
        self.assertNotEqual(
            document['settings']['AUTHENTICATION_BACKENDS'],
            listed,
        )

    def test_backend_list_and_tuple_record_the_same_sequence(self):
        default = list(global_settings.AUTHENTICATION_BACKENDS)
        with override_settings(AUTHENTICATION_BACKENDS=tuple(default)):
            as_tuple = yaml.safe_load(render_policy_sql_bytes())['settings']
        with override_settings(AUTHENTICATION_BACKENDS=list(default)):
            as_list = yaml.safe_load(render_policy_sql_bytes())['settings']
        self.assertEqual(as_tuple['AUTHENTICATION_BACKENDS'], default)
        self.assertEqual(as_list['AUTHENTICATION_BACKENDS'], default)

    def test_path_and_inactive_settings_stay_out_of_the_block(self):
        with override_settings(
            USE_TZ=False,
            BASE_DIR='/tmp/trusts-policy-root',
            TRUSTS_POLICY_LOCKFILE='/tmp/trusts-policy.lock.yaml',
            TRUSTS_POLICY_DATABASE='default',
            TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True,
        ):
            recorded = _settings_block(_document_handle())
        self.assertEqual(
            set(recorded),
            {
                'TRUSTS_SQL_BIND_ONCE',
                'AUTH_USER_MODEL',
                'AUTHENTICATION_BACKENDS',
            },
        )

    def test_non_default_auth_user_model_is_recorded(self):
        env = os.environ.copy()
        env.pop('DJANGO_SETTINGS_MODULE', None)
        pythonpath = [str(ROOT)]
        existing = env.get('PYTHONPATH')
        if existing:
            pythonpath.append(existing)
        env['PYTHONPATH'] = os.pathsep.join(pythonpath)
        result = subprocess.run(
            [sys.executable, '-c', _CUSTOM_USER_SOURCE],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)
        self.assertIn('custom-user-settings', result.stdout)


class RegisterLabelTest(SimpleTestCase):

    def test_labels_are_on_the_row_when_given_and_absent_when_omitted(self):
        plain = _grant_handle('documents.backends.PlainGrant')
        named = _grant_handle(
            'documents.backends.NamedGrant',
            name='direct_grant',
            description='A user grant on the document.',
        )
        name_only = _grant_handle(
            'documents.backends.NameOnly',
            name='direct_grant',
        )
        description_only = _grant_handle(
            'documents.backends.DescriptionOnly',
            description='A user grant on the document.',
        )
        plain_row = _trust_row(plain)
        named_row = _trust_row(named)
        name_row = _trust_row(name_only)
        description_row = _trust_row(description_only)
        self.assertNotIn('name', plain_row)
        self.assertNotIn('description', plain_row)
        self.assertEqual(
            list(named_row)[:4],
            ['id', 'name', 'description', 'root'],
        )
        self.assertEqual(named_row['name'], 'direct_grant')
        self.assertEqual(named_row['description'], 'A user grant on the document.')
        self.assertEqual(name_row['name'], 'direct_grant')
        self.assertNotIn('description', name_row)
        self.assertNotIn('name', description_row)
        self.assertEqual(
            description_row['description'],
            'A user grant on the document.',
        )
        self.assertEqual(plain_row['id'], 'myapp__DocumentGrant__document')
        self.assertEqual(named_row['id'], plain_row['id'])
        self.assertEqual(name_row['id'], plain_row['id'])
        self.assertEqual(description_row['id'], plain_row['id'])

    def test_name_does_not_change_assigned_ids(self):
        def same_user(row):
            return row.user == row.user

        def same_permission(row):
            return row.permission == row.permission

        def build(path, *, labeled):
            handle = compiler()
            handle.path = path
            first = {}
            second = {}
            if labeled:
                first = {
                    'name': 'open_grant',
                    'description': 'Same user on the grant row.',
                }
                second = {
                    'name': 'closed_grant',
                    'description': 'Same permission on the grant row.',
                }
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                condition=same_user,
                **first,
            )
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                condition=same_permission,
                **second,
            )
            document = yaml.safe_load(render_configured_policy(handle))
            return document['backends'][0]['contents'][0]['trusts']

        plain = build('documents.backends.PlainIds', labeled=False)
        named = build('documents.backends.NamedIds', labeled=True)
        expected = [
            'myapp__DocumentGrant__document__cond',
            'myapp__DocumentGrant__document__cond__2',
        ]
        self.assertEqual([row['id'] for row in plain], expected)
        self.assertEqual([row['id'] for row in named], expected)
        self.assertNotIn('name', plain[0])
        self.assertEqual(named[0]['name'], 'open_grant')
        self.assertEqual(named[1]['name'], 'closed_grant')
        self.assertNotIn('open_grant', named[0]['id'])
        self.assertNotIn('closed_grant', named[1]['id'])

    def test_delegation_labels_do_not_change_its_id(self):
        def build(path, **labels):
            handle = compiler()
            handle.path = path
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
            handle.register(
                trust=DocumentDelegation,
                delegate='delegate',
                sponsor='sponsor',
                content='document',
                condition=lambda relationship, permission: (
                    relationship.allowed_permissions.contains(permission)
                ),
                **labels,
            )
            document = yaml.safe_load(render_configured_policy(handle))
            content = document['backends'][0]['contents'][0]
            return content['delegations'][0], content['trusts'][0]

        plain, plain_grant = build('documents.backends.PlainDelegation')
        named, named_grant = build(
            'documents.backends.NamedDelegation',
            name='sponsor_delegation',
            description='Delegate uses the sponsor grant on the document.',
        )
        self.assertEqual(plain['id'], 'myapp__DocumentDelegation__document__cond')
        self.assertEqual(named['id'], plain['id'])
        self.assertNotIn('name', plain)
        self.assertNotIn('description', plain)
        self.assertEqual(
            list(named)[:3],
            ['id', 'name', 'description'],
        )
        self.assertEqual(named['name'], 'sponsor_delegation')
        self.assertEqual(
            named['description'],
            'Delegate uses the sponsor grant on the document.',
        )
        self.assertNotIn('name', plain_grant)
        self.assertNotIn('name', named_grant)

    def test_a_different_name_is_still_a_duplicate(self):
        handle = compiler()
        handle.register(
            trust=DocumentGrant,
            user='user',
            permission='permission',
            content='document',
            name='first_grant',
            description='First text.',
        )
        with self.assertRaises(TrustsConfigurationError) as caught:
            handle.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
                name='second_grant',
                description='Second text.',
            )
        self.assertIn('Duplicate registration', str(caught.exception))
        self.assertEqual(len(handle.records), 1)
        self.assertEqual(handle.records[0].name, 'first_grant')
        self.assertEqual(handle.records[0].description, 'First text.')

    def test_bad_labels_raise_at_register_and_store_nothing(self):
        handle = compiler()
        handle.path = 'documents.backends.BadLabels'
        for bad in ('', 'has space', 'has-dash', 'name1', 1, True, b'abc'):
            with self.subTest(name=bad):
                with self.assertRaises(TrustsConfigurationError) as caught:
                    handle.register(
                        trust=DocumentGrant,
                        user='user',
                        permission='permission',
                        content='document',
                        name=bad,
                    )
                self.assertIn('letters and underscores', str(caught.exception))
        for bad in (1, True, b'text', ['words']):
            with self.subTest(description=bad):
                with self.assertRaises(TrustsConfigurationError) as caught:
                    handle.register(
                        trust=DocumentGrant,
                        user='user',
                        permission='permission',
                        content='document',
                        description=bad,
                    )
                self.assertIn('description must be a string', str(caught.exception))
        self.assertEqual(handle.records, ())
        self.assertEqual(handle.delegations, ())

    def test_recorder_replays_labels_and_drops_a_rejected_call(self):
        config = _probe()
        recorder = _recorder(config)
        with self.assertRaises(TrustsConfigurationError):
            recorder.register(**_grant(name='1bad'))
        empty = compiler()
        recorder.play(empty)
        self.assertEqual(empty.records, ())
        recorder.register(**_grant(
            name='direct_grant',
            description='A user grant on the document.',
        ))
        recorder.freeze()
        target = compiler()
        target.path = 'documents.backends.ReplayedGrant'
        recorder.play(target)
        self.assertEqual(target.records[0].name, 'direct_grant')
        row = _trust_row(target)
        self.assertEqual(row['id'], 'myapp__DocumentGrant__document')
        self.assertEqual(row['name'], 'direct_grant')
        self.assertEqual(row['description'], 'A user grant on the document.')
