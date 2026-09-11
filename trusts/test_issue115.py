"""#115: user README, package copy, and verified final-API example.

Documentation/package alignment only. Exercises the README consumer
shape: ordinary models, ``TrustModelBackendMixin`` subclass,
``TrustsImplementationConfig``, one ``Ref`` registration, ``has_perm``,
authorized queryset, and ``permission_required``.
"""

import ast
import re
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin
from trusts.core import Ref
from trusts.decorators import permission_required
from trusts.query import AuthorizedManager, AuthorizedQuerySet


ROOT = Path(__file__).resolve().parents[1]
FOLDER_BACKEND = 'trusts.test_issue115.FolderBackend'


class FolderBackend(TrustModelBackendMixin, ModelBackend):
    pass


class FolderAuthConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'readme_folder_auth'
    trusts_backend_paths = (FOLDER_BACKEND,)


class _AppsView(object):
    def __init__(self, configs, ready=True):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return tuple(self._configs)

    def is_installed(self, name):
        return False


def _bind(config_cls, configs=None, ready=True):
    config = config_cls('tests', tests_module)
    view = _AppsView(
        configs if configs is not None else [config],
        ready=ready,
    )
    config.apps = view
    if configs is None:
        view._configs = [config]
    return config


def _readme_models():
    """Ordinary application-owned models from the README example.

    The README uses ``settings.AUTH_USER_MODEL``. Isolated apps resolve
    that string only after ``auth.User`` is loaded, so the live proof
    binds the same user model class Django would resolve.
    """
    User = get_user_model()

    class Folder(models.Model):
        title = models.CharField(max_length=40)
        objects = AuthorizedManager()

        class Meta:
            app_label = 'trusts_tests'

    class FolderGrant(models.Model):
        folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'

    return Folder, FolderGrant


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


def _perm(model, codename):
    ct, _created = ContentType.objects.get_or_create(
        app_label=model._meta.app_label,
        model=model._meta.model_name,
    )
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _python_fences(text):
    return re.findall(r'```python\n(.*?)```', text, flags=re.DOTALL)


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


class ReadmePackageCopyTest(SimpleTestCase):
    def test_user_readme_is_not_internal_status(self):
        readme = (ROOT / 'README.md').read_text()
        forbidden = (
            'Step I',
            'Step II',
            'Step III',
            'C1',
            'C2',
            'Z1',
            'pair pin',
            'baton',
            'code budget',
            '1.0.0.dev1',
            '1.0.0.dev2',
            '1.0.0.dev3',
            '11058641',
            '94e0fa',
            'f0b25c',
            'kernel_config',
            'trusts.core_backends',
            'from trusts.backends import TrustModelBackend\n',
            'from trusts.models import Trust',
            'settlor',
            'trustee',
            'multiple organizations',
        )
        offenders = [needle for needle in forbidden if needle in readme]
        self.assertEqual(offenders, [])
        self.assertIn('non-standalone Python dependency', readme)
        self.assertIn("Do **not** list `'trusts'` in `INSTALLED_APPS`", readme)
        self.assertIn('from trusts.backends import TrustModelBackendMixin', readme)
        self.assertIn('from trusts.apps import TrustsImplementationConfig', readme)
        self.assertIn('from trusts.core import Ref', readme)
        self.assertIn('AuthorizedQuerySet(Folder).authorized(user, perm)', readme)
        self.assertIn('user.has_perm(', readme)
        self.assertIn('@permission_required(', readme)
        self.assertIn('django-trusts-zero', readme)
        self.assertIn('django-trusts-gh-permissions', readme)
        self.assertIn('forthcoming', readme.lower())
        self.assertIn('Windows', readme)
        self.assertIn('migrates.md', readme)
        self.assertIn('DEV.md', readme)
        self.assertIn('BeeDesk, Inc.', readme)
        self.assertIn('2015-2026', readme)

    def test_dev_md_is_contributor_history_and_corrects_the_library_cut(self):
        dev = (ROOT / 'DEV.md').read_text()
        header = dev[:900].lower()
        self.assertIn('contributor', header)
        self.assertIn('internal', header)
        self.assertIn('README.md', dev)
        self.assertNotIn('readme = "DEV.md"', (ROOT / 'pyproject.toml').read_text())
        self.assertIn('kernel_config()', dev)
        self.assertIn('no Django `AppConfig`', dev)
        self.assertIn('trusts.core_backends', dev)
        self.assertIn('TrustModelBackendMixin', dev)
        self.assertIn('1.0.0.dev3', dev)
        self.assertIn('docs/legacy-baseline.md', dev)
        self.assertIn('docs/support-matrix.md', dev)

    def test_pyproject_and_license_match_the_library(self):
        pyproject = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('name = "django-trusts"', pyproject)
        self.assertIn('version = "1.0.0.dev3"', pyproject)
        self.assertIn('readme = "README.md"', pyproject)
        self.assertNotIn('readme = "DEV.md"', pyproject)
        self.assertIn('license = "BSD-2-Clause"', pyproject)
        self.assertIn(
            'Implementation-neutral Django authorization library',
            pyproject,
        )
        self.assertNotIn('multiple organizations', pyproject)
        self.assertNotIn('"organizations"', pyproject)
        license_text = (ROOT / 'LICENSE').read_text()
        self.assertIn('Copyright (c) 2015-2026, BeeDesk, Inc.', license_text)
        self.assertNotIn('and contributors', license_text.split('THIS SOFTWARE')[0])
        self.assertIn('All rights reserved.', license_text)

    def test_readme_fences_are_real_python_and_use_the_final_api(self):
        readme = (ROOT / 'README.md').read_text()
        fences = _python_fences(readme)
        self.assertGreaterEqual(len(fences), 4)
        for fence in fences:
            ast.parse(fence)
        joined = '\n'.join(fences)
        self.assertIn('class FolderBackend(TrustModelBackendMixin, ModelBackend)', joined)
        self.assertIn('class FolderAuthConfig(TrustsImplementationConfig)', joined)
        self.assertIn('grant = Ref(FolderGrant)', joined)
        self.assertIn('self.registry.register(', joined)
        self.assertIn('myapp.apps.FolderAuthConfig', joined)
        self.assertNotIn("'trusts'", joined)
        self.assertIn('FolderGrant.objects.create(', joined)
        self.assertIn("user.has_perm('myapp.change_folder', folder)", joined)
        self.assertIn('AuthorizedQuerySet(Folder).authorized(user, perm)', joined)
        self.assertIn('fieldlookups_kwargs', joined)
        self.assertNotIn('trusts.core_backends', joined)
        self.assertNotIn('kernel_config', joined)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ReadmeExampleLiveTest(TransactionTestCase):
    def test_readme_example_has_perm_queryset_and_decorator(self):
        Folder, FolderGrant = _readme_models()
        with _tables(Folder, FolderGrant):
            User = get_user_model()
            alice = User.objects.create_user(
                username='readme-alice', password='x',
            )
            bob = User.objects.create_user(
                username='readme-bob', password='x',
            )
            folder_a = Folder.objects.create(title='A')
            folder_b = Folder.objects.create(title='B')
            perm = _perm(Folder, 'change_folder')
            FolderGrant.objects.create(
                folder=folder_a, user=alice, permission=perm,
            )
            code = '%s.change_folder' % Folder._meta.app_label

            owner = _bind(FolderAuthConfig, ready=False)
            with override_settings(AUTHENTICATION_BACKENDS=(
                'django.contrib.auth.backends.ModelBackend',
                FOLDER_BACKEND,
            )):
                owner.ready()
                grant = Ref(FolderGrant)
                owner.registry.register(
                    content=grant.folder,
                    user=grant.user,
                    permission=grant.permission,
                )
                with patch(
                    'trusts.apps.implementation_configs',
                    return_value=(owner,),
                ):
                    backend = FolderBackend()
                    self.assertTrue(backend.has_perm(alice, code, folder_a))
                    self.assertFalse(backend.has_perm(alice, code, folder_b))
                    self.assertFalse(backend.has_perm(bob, code, folder_a))
                    self.assertTrue(alice.has_perm(code, folder_a))
                    self.assertFalse(alice.has_perm(code, folder_b))
                    self.assertFalse(bob.has_perm(code, folder_a))

                    qs = AuthorizedQuerySet(Folder).authorized(alice, perm)
                    with self.assertNumQueries(1):
                        pks = set(qs.values_list('pk', flat=True))
                    self.assertEqual(pks, {folder_a.pk})
                    self.assertFalse(
                        AuthorizedQuerySet(Folder).authorized(bob, perm).exists()
                    )

                    from django.core.exceptions import PermissionDenied
                    from trusts import decorators as dec

                    @permission_required(
                        code,
                        fieldlookups_kwargs={'pk': 'folder_id'},
                    )
                    def edit_folder(request, folder_id):
                        return folder_id

                    # isolate_apps models are invisible to ContentType.model_class().
                    # The decorator's remaining work is user.has_perms on that
                    # queryset — the same surface Django views use.
                    granted = Folder.objects.filter(pk=folder_a.pk)
                    denied = Folder.objects.filter(pk=folder_b.pk)
                    with patch.object(dec, '_get_permissible_items', return_value=granted):
                        self.assertEqual(
                            edit_folder(_request(alice), folder_id=folder_a.pk),
                            folder_a.pk,
                        )
                        with self.assertRaises(PermissionDenied):
                            edit_folder(_request(bob), folder_id=folder_a.pk)
                    with patch.object(dec, '_get_permissible_items', return_value=denied):
                        with self.assertRaises(PermissionDenied):
                            edit_folder(_request(alice), folder_id=folder_b.pk)
