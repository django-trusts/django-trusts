# see https://docs.djangoproject.com/en/stable/topics/testing/advanced/#using-the-django-test-runner-to-test-reusable-applications
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings


# Kernel-only suite: no Zero, no concrete Trust models.
KERNEL_SUITE = [
    'trusts.test_issue57',
    'trusts.test_issue60',
    'trusts.test_issue65',
    'trusts.test_issue83',
    'trusts.test_issue92',
    'trusts.test_issue96',
    'trusts.test_issue98',
    'trusts.test_issue100',
    'trusts.test_issue103',
]

# C1 ran ``run_tests(['trusts'])``. Pair re-runs that full package except
# explicitly kernel-only C2 assertions (``test_issue96``: no label
# ``trusts``, no Trust, shim ImportError without Zero).
PAIR_LEGACY_SUITE = [
    'trusts.tests',
    'trusts.test_issue4',
    'trusts.test_issue8',
    'trusts.test_issue23',
    'trusts.test_issue29',
    'trusts.test_issue54',
    'trusts.test_issue57',
    'trusts.test_issue60',
    'trusts.test_issue65',
    'trusts.test_issue67',
    'trusts.test_issue70',
    'trusts.test_issue72',
    'trusts.test_issue75',
    'trusts.test_issue77',
    'trusts.test_issue80',
    'trusts.test_issue83',
    'trusts.test_issue85',
    'trusts.test_issue87',
    'trusts.test_issue89',
    'trusts.test_issue92',
    'trusts.test_issue98',
    'trusts.test_issue100',
    'trusts.test_issue103',
]


def runtests(suite=None):
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(suite if suite is not None else KERNEL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests(sys.argv[1:] or None)
