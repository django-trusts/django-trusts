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
    'trusts.test_issue16',
    'trusts.test_issue57',
    'trusts.test_issue60',
    'trusts.test_issue65',
    'trusts.test_issue83',
    'trusts.test_issue92',
    'trusts.test_issue96',
    'trusts.test_issue98',
    'trusts.test_issue100',
    'trusts.test_issue103',
    'trusts.test_issue108',
    'trusts.test_issue111',
    'trusts.test_issue115',
]

# C1 ran ``run_tests(['trusts'])``. Pair re-runs that full package except
# kernel-only identity assertions (``test_issue96`` / ``111``) and tests
# that still need a core product module or a second test-backend owner
# Zero IIa does not provide (admin/views templates, multi-path
# ``tests.backends.*`` hosts).
PAIR_LEGACY_SUITE = [
    'trusts.tests',
    'trusts.test_issue4',
    'trusts.test_issue16',
    'trusts.test_issue29',
    'trusts.test_issue54',
    'trusts.test_issue57',
    'trusts.test_issue60',
    'trusts.test_issue65',
    'trusts.test_issue67',
    'trusts.test_issue70',
    'trusts.test_issue72',
    'trusts.test_issue83',
    'trusts.test_issue92',
    'trusts.test_issue98',
    'trusts.test_issue100',
    'trusts.test_issue103',
    'trusts.test_issue108',
]


def runtests(suite=None):
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(suite if suite is not None else KERNEL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests(sys.argv[1:] or None)
