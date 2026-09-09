#!/usr/bin/env python3
"""Import-smoke the installed django-trusts wheel from outside the checkout.

This must not be run with the repository root as cwd or on sys.path. A
passing result means trusts, Trust, and TrustModelBackend were loaded from
the installed distribution, not the source tree.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


# Historical installable-package locations. Presence is checked without
# executing the module: a leaked trusts.tests imports tests.models, and
# that ImportError is not proof the file is absent from the wheel.
ABSENT_TEST_MODULES = [
    'trusts.tests',
    'trusts.test_issue4',
    'trusts.test_issue8',
    'trusts.test_issue23',
    'trusts.test_issue25',
    'trusts.test_issue26',
    'trusts.test_issue29',
    'trusts.test_issue33',
]


def find_shipped_modules(names):
    """Return names that have a finder/loader. Does not execute the modules."""
    shipped = []
    for name in names:
        try:
            spec = importlib.util.find_spec(name)
        except ModuleNotFoundError:
            continue
        if spec is not None:
            shipped.append(name)
    return shipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--checkout',
        required=True,
        help='Absolute path to the repository checkout that must not be imported',
    )
    args = parser.parse_args()
    checkout = Path(args.checkout).resolve()
    cwd = Path.cwd().resolve()

    if cwd == checkout or checkout in cwd.parents:
        raise SystemExit(
            'Refuse to run from the checkout (%s). cd to a temporary directory.' % cwd
        )

    leaked = []
    for entry in sys.path:
        if entry == '':
            if cwd == checkout:
                leaked.append("'' (cwd is the checkout)")
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue
        # Only the checkout root can shadow the installed `trusts` package.
        if resolved == checkout:
            leaked.append(entry)
    if leaked:
        raise SystemExit('Checkout leaked onto sys.path: %s' % leaked)

    from django.conf import settings

    settings.configure(
        SECRET_KEY='wheel-import-smoke',
        USE_TZ=True,
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'trusts',
        ],
        AUTHENTICATION_BACKENDS=['trusts.backends.TrustModelBackend'],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    )

    import django
    django.setup()

    import trusts
    from trusts.models import Trust, Junction
    from trusts.context import Context
    from trusts.backends import TrustModelBackend
    from django_trusts import TQ, condition_refs

    trusts_file = Path(trusts.__file__).resolve()
    if checkout == trusts_file or checkout in trusts_file.parents:
        raise SystemExit('Imported trusts from the checkout: %s' % trusts_file)
    if 'site-packages' not in str(trusts_file) and 'dist-packages' not in str(trusts_file):
        raise SystemExit('trusts.__file__ is not a site-packages install: %s' % trusts_file)

    leaked_tests = find_shipped_modules(ABSENT_TEST_MODULES)
    if leaked_tests:
        raise SystemExit('Test modules must not ship in the wheel: %s' % leaked_tests)

    print('wheel import ok')
    print('django', django.get_version())
    print('trusts.__file__', trusts_file)
    print('Trust', Trust)
    print('Junction', Junction)
    print('Context', Context)
    print('TrustModelBackend', TrustModelBackend)
    print('TQ', TQ)
    print('condition_refs', condition_refs)
    print('absent test modules', ' '.join(ABSENT_TEST_MODULES))
    return 0


if __name__ == '__main__':
    sys.exit(main())
