# see https://docs.djangoproject.com/en/stable/topics/testing/advanced/#using-the-django-test-runner-to-test-reusable-applications
import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings


# Kernel-only suite: no Zero, no concrete Trust models. Historical
# Content/Trust tests stay in the tree for a paired Zero install.
KERNEL_SUITE = [
    'trusts.test_issue57',
    'trusts.test_issue60',
    'trusts.test_issue65',
    'trusts.test_issue83',
    'trusts.test_issue92',
    'trusts.test_issue96',
]


def runtests():
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(KERNEL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests()
