# see https://docs.djangoproject.com/en/stable/topics/testing/advanced/#using-the-django-test-runner-to-test-reusable-applications
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings


# Library-only suite: no Zero, no concrete Trust models, no shipped
# trusts/test*.py modules.
KERNEL_SUITE = [
    'tests.core.test_issue4',
    'tests.core.test_issue16',
    'tests.core.test_issue18',
    'tests.core.test_issue29',
    'tests.core.test_issue54',
    'tests.core.test_issue57',
    'tests.core.test_issue60',
    'tests.core.test_issue65',
    'tests.core.test_issue67',
    'tests.core.test_issue70',
    'tests.core.test_issue72',
    'tests.core.test_issue75',
    'tests.core.test_issue77',
    'tests.core.test_issue80',
    'tests.core.test_issue83',
    'tests.core.test_issue89',
    'tests.core.test_issue92',
    'tests.core.test_issue96',
    'tests.core.test_issue98',
    'tests.core.test_issue100',
    'tests.core.test_issue103',
    'tests.core.test_issue108',
    'tests.core.test_issue111',
    'tests.core.test_issue115',
    'tests.core.test_issue129',
]

# Kernel modules that remain valid against an installed Zero owner.
# Historical Trust/Content/Junction/Role coverage runs from the Zero
# checkout (see scripts/run-z1-pair-tests.py), not from core paths.
PAIR_KERNEL_SUITE = [
    'tests.core.test_issue4',
    'tests.core.test_issue16',
    'tests.core.test_issue18',
    'tests.core.test_issue29',
    'tests.core.test_issue54',
    'tests.core.test_issue57',
    'tests.core.test_issue60',
    'tests.core.test_issue65',
    'tests.core.test_issue67',
    'tests.core.test_issue70',
    'tests.core.test_issue72',
    'tests.core.test_issue75',
    'tests.core.test_issue77',
    'tests.core.test_issue80',
    'tests.core.test_issue83',
    'tests.core.test_issue89',
    'tests.core.test_issue92',
    'tests.core.test_issue98',
    'tests.core.test_issue100',
    'tests.core.test_issue103',
    'tests.core.test_issue108',
    'tests.core.test_issue129',
]


def runtests(suite=None):
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(suite if suite is not None else KERNEL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests(sys.argv[1:] or None)
