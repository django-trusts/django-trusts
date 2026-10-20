"""Custom AUTH_USER_MODEL imports trusts.query while its module loads.

The documented manager mixin is imported at model-definition time, before
the swappable user model is registered. Startup must finish, migrate, and
pass ``check``.
"""

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]

_BOOT_SOURCE = """\
from django.conf import settings
settings.configure(
    SECRET_KEY='custom-user-boot',
    USE_TZ=True,
    DEFAULT_AUTO_FIELD='django.db.models.AutoField',
    AUTH_USER_MODEL='custom_user.User',
    INSTALLED_APPS=(
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'tests.custom_user.apps.CustomUserConfig',
        'trusts.apps.TrustsImplementationConfig',
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
from django.contrib.auth import get_user_model
from django.core.management import call_command
from trusts.query import PermittedUsersManagerMixin
user = get_user_model()
assert user._meta.label == 'custom_user.User', user._meta.label
assert issubclass(user.objects.__class__, PermittedUsersManagerMixin)
call_command('migrate', verbosity=0, run_syncdb=True)
call_command('check')
print('custom-user-booted')
"""


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


class CustomUserStartupTests(SimpleTestCase):
    def test_documented_manager_mixin_boots_migrates_and_checks(self):
        stdout = _run_isolated(_BOOT_SOURCE)
        self.assertIn('custom-user-booted', stdout)
