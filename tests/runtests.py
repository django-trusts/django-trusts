# see https://docs.djangoproject.com/en/stable/topics/testing/advanced/#using-the-django-test-runner-to-test-reusable-applications
import os
import pkgutil
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings

import tests.core as _core_package


# These modules assume the kernel host. They are not valid against an
# installed Zero owner. Historical Trust coverage runs from the Zero
# checkout (see scripts/run-z1-pair-tests.py), not from core paths.
_KERNEL_ONLY = frozenset((
    'tests.core.test_backend_or',
    'tests.core.test_custom_user',
    'tests.core.test_issue96',
    'tests.core.test_issue111',
    'tests.core.test_issue115',
))


def _discover_core_modules():
    """Every ``tests.core.test_*`` module or package, in stable order."""
    found = []
    for module in pkgutil.iter_modules(_core_package.__path__):
        if module.name.startswith('test_'):
            found.append('tests.core.' + module.name)
    return tuple(sorted(found))


KERNEL_SUITE = _discover_core_modules()
PAIR_KERNEL_SUITE = tuple(
    name for name in KERNEL_SUITE
    if name not in _KERNEL_ONLY
)


def runtests(suite=None):
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(suite if suite is not None else KERNEL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests(sys.argv[1:] or None)
