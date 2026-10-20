"""Settings for the PostgreSQL and MySQL along jobs.

The kernel settings mark ``myapp`` and ``trusts_tests`` as unmigrated.
Django syncs those apps before ``auth`` migrations, and PostgreSQL and
MySQL then reject the foreign key to ``auth_user``. These jobs only need
``auth``, the kernel host, and the trusts app. Importing that app
registers ``Meta.permission_conditions`` before models load.
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
)
MIGRATION_MODULES = {}
