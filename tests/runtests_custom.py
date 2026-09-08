# Isolated runner for issue #26 custom AUTH_USER_MODEL.
# Uses tests.custom_settings so AUTH_USER_MODEL / TRUSTS_ENTITY_MODEL
# are selected before migrate. Group and Permission stay auth.*.
import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.custom_settings'
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)

import django
from django.test.utils import get_runner
from django.conf import settings


def runtests():
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=False)
    failures = test_runner.run_tests(['tests.custom_content'])
    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests()
