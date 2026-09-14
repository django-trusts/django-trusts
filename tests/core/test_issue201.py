"""#201 / #189 B2: authorization_required fail-closed boundaries.

Public ``authorization_required`` declaration, readiness/preflight, and
supported-path bounds only. Does not restore legacy request decorators,
patch ``granted`` / ``_authorization_grant_q`` / compiler internals, or
assert private registry/IR shape.

``granted_q is None`` after a complete auth-Permission preflight is
deferred: ``PlanQueryCompiler.complete_exists`` and
``_plan_is_auth_permission`` share the records gate, so that 403/404
split is not produced by a documented public configuration without a
test-only compiler or private patching.
"""

import os
import subprocess
import sys
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest
from django.test import SimpleTestCase, TestCase

from tests.core import KernelHostRequiredMixin
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.apps import implementation_for_path
from trusts.core import TrustsConfigurationError
from trusts.decorators import authorization_required


PERM = 'myapp.change_document'
ROOT = Path(__file__).resolve().parents[2]


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


def _run_isolated(source):
    env = os.environ.copy()
    env.pop('DJANGO_SETTINGS_MODULE', None)
    pythonpath = [str(ROOT)]
    existing = env.get('PYTHONPATH')
    if existing:
        pythonpath.append(existing)
    env['PYTHONPATH'] = os.pathsep.join(pythonpath)
    result = subprocess.run(
        [sys.executable, '-c', source],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


_NOT_READY_POPULATE_SOURCE = """\
from django.conf import settings
settings.configure(
    SECRET_KEY='issue201-not-ready',
    USE_TZ=True,
    DEFAULT_AUTO_FIELD='django.db.models.AutoField',
    INSTALLED_APPS=(
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'tests.myapp.apps.DocumentConfig',
        'tests.core.issue201_not_ready.NotReadyPopulateProbeConfig',
    ),
    AUTHENTICATION_BACKENDS=(
        'tests.myapp.backends.DocumentBackend',
    ),
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    },
    MIGRATION_MODULES={'myapp': None},
)
import django
django.setup()
"""


_PARTIAL_DECLARATION_SOURCE = """\
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
import django
django.setup()
from django.core.checks import run_checks
from tests.myapp.models import Document
from trusts.core import TrustsConfigurationError
from trusts.decorators import authorization_required

try:
    authorization_required(
        Document, 'myapp.change_document', ('partial_201', ''),
    )
except TrustsConfigurationError:
    pass
else:
    raise SystemExit('expected TrustsConfigurationError')

messages = [
    message for message in run_checks()
    if getattr(message, 'id', None) == 'trusts.E008'
]
for message in messages:
    if 'partial_201' in message.msg:
        raise SystemExit('partial declaration leaked into trusts.E008')
print('partial-declaration-ok')
"""


class AuthorizationRequiredDeclarationTest(TestCase):
    def test_declaration_rejects_invalid_permission_and_names_at_zero_sql(self):
        with self.assertNumQueries(0):
            with self.assertRaises(TypeError) as ctx:
                authorization_required(Document, None)
            self.assertIn('app_label.codename', str(ctx.exception))
            with self.assertRaises(TypeError):
                authorization_required(Document, 123)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                authorization_required(Document, '.change_document')
            self.assertIn('app_label.codename', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(Document, 'myapp.')
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(Document, '.')
            with self.assertRaises(TrustsConfigurationError) as ctx:
                authorization_required(Document, PERM, ('',))
            self.assertIn('malformed', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(Document, PERM, (' padded ',))
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(Document, PERM, ('has:colon',))
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(Document, PERM, (None,))
            with self.assertRaises(TrustsConfigurationError):
                authorization_required(
                    Document, PERM, ('non_confidential', ' bad'),
                )

    def test_failed_declaration_is_absent_from_public_system_checks(self):
        stdout = _run_isolated(_PARTIAL_DECLARATION_SOURCE)
        self.assertIn('partial-declaration-ok', stdout)


class AuthorizationRequiredPopulateReadinessTest(SimpleTestCase):
    def test_populate_window_fails_closed_at_zero_sql(self):
        stdout = _run_isolated(_NOT_READY_POPULATE_SOURCE)
        self.assertIn('not-ready-populate-ok', stdout)


class AuthorizationRequiredReadinessPreflightTest(
    KernelHostRequiredMixin, TestCase,
):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-201', password='x')
        self.bob = User.objects.create_user('bob-201', password='x')
        self.superuser = User.objects.create_superuser(
            'root-201', password='x', email='root-201@example.com',
        )
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.open_doc = Document.objects.create(title='open-201', confidential=False)
        self.secret = Document.objects.create(title='secret-201', confidential=True)
        for index in range(4):
            Document.objects.create(title='extra-%s' % index, confidential=False)
        DocumentGrant.objects.create(
            document=self.open_doc, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.secret, user=self.alice, permission=self.change,
        )

    def test_missing_and_unbound_selected_name_fail_before_candidate_or_superuser(
        self,
    ):
        @authorization_required(Document, PERM, ('missing_201',))
        def _missing(request, pk):
            return 'no'

        for user in (self.alice, self.superuser):
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    _missing(_request(user), pk=self.open_doc.pk)
                self.assertIn('missing_201', str(ctx.exception))

        @authorization_required(Document, PERM, ('non_confidential',))
        def _filtered(request, pk):
            return 'ok'

        registry = implementation_for_path(
            DOCUMENT_BACKEND,
        ).configured_backend().registry
        previous = registry.condition_lookup
        try:
            registry.set_condition_lookup(None)
            with self.assertNumQueries(0):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    _filtered(_request(self.alice), pk=self.open_doc.pk)
                self.assertIn('non_confidential', str(ctx.exception))
                with self.assertRaises(TrustsConfigurationError):
                    _filtered(_request(self.superuser), pk=self.open_doc.pk)
        finally:
            registry.set_condition_lookup(previous)
        self.assertIs(registry.condition_lookup, previous)

        with self.assertNumQueries(1):
            self.assertEqual(
                _filtered(_request(self.alice), pk=self.open_doc.pk),
                'ok',
            )

    def test_supported_grant_stays_one_sql_and_conditions_do_not_create_grants(
        self,
    ):
        @authorization_required(Document, PERM)
        def _edit(request, pk):
            return 'ok'

        @authorization_required(Document, PERM, ('non_confidential',))
        def _filtered(request, pk):
            return 'ok'

        with self.assertNumQueries(1):
            self.assertEqual(_edit(_request(self.alice), pk=self.open_doc.pk), 'ok')
        with self.assertNumQueries(2):
            with self.assertRaises(PermissionDenied):
                _edit(_request(self.bob), pk=self.open_doc.pk)
        with self.assertNumQueries(2):
            with self.assertRaises(Http404):
                _edit(_request(self.alice), pk=self.open_doc.pk + 1000)

        with self.assertNumQueries(1):
            self.assertEqual(
                _filtered(_request(self.alice), pk=self.open_doc.pk),
                'ok',
            )
        with self.assertRaises(PermissionDenied):
            _filtered(_request(self.alice), pk=self.secret.pk)
        with self.assertRaises(PermissionDenied):
            _filtered(_request(self.bob), pk=self.open_doc.pk)


class Issue201SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue201', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue201', PAIR_KERNEL_SUITE)
