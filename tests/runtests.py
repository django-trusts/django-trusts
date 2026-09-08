# see https://docs.djangoproject.com/en/stable/topics/testing/advanced/#using-the-django-test-runner-to-test-reusable-applications
import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings


# Explicit module labels so core and regression tests run without relying on
# unittest's test*.py filename pattern. The isolated custom-user suite stays
# on tests.runtests_custom (tests.custom_content) and is not included here.
NORMAL_SUITE = [
    'tests.core.test_core',
    'tests.regressions.test_issue_4',
    'tests.regressions.test_issue_8',
    'tests.regressions.test_issue_23',
    'tests.regressions.test_issue_25',
    'tests.regressions.test_issue_26',
    'tests.regressions.test_issue_29',
    'tests.regressions.test_issue_33',
]


def runtests():
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(NORMAL_SUITE)
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests()
