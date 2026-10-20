"""Settings for the PostgreSQL and MySQL along jobs.

The kernel settings mark ``myapp`` and ``trusts_tests`` as unmigrated.
Django syncs those apps before ``auth`` migrations, and PostgreSQL and
MySQL then reject the foreign key to ``auth_user``. These jobs install
``auth``, the kernel host, and ``AlongCoreConfig``. That last app owns
modules under ``tests.core`` and has no models, so nothing is synced
ahead of ``auth``. Importing the host config imports ``trusts.apps``,
which registers ``Meta.permission_conditions`` before models load.
"""

import os

if os.environ.get('TRUSTS_TEST_DATABASE') == 'mysql':
    try:
        import MySQLdb  # noqa: F401
    except ImportError:
        import pymysql

        pymysql.install_as_MySQLdb()

from tests.settings import *  # noqa: E402,F403

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'tests.kernel_host.apps.KernelHostConfig',
    'tests.core.apps.AlongCoreConfig',
)
MIGRATION_MODULES = {}
