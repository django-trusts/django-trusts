"""PostgreSQL settings for isolated OrderedFold regressions.

Import the kernel test settings, then drop historical test models so
``create_test_db`` only migrates Django contrib apps.
"""

from tests.settings import *  # noqa: F403

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'trusts',
    'tests.kernel_host.apps.KernelHostConfig',
    'tests.fold_apps.FoldTestsConfig',
)
