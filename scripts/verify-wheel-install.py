#!/usr/bin/env python3
"""Import-smoke the installed django-trusts *kernel* wheel.

Must not run with the repository root as cwd or on sys.path. A passing
result means kernel modules loaded from the installed distribution, the
wheel does not ship ``trusts.zero``, and historical test modules are
absent.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


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

ABSENT_ZERO_MODULES = [
    'trusts.zero',
    'trusts.zero.models',
    'trusts.zero.backends',
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
            'trusts.apps.KernelConfig',
        ],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    )

    import django
    django.setup()

    import trusts
    from trusts.apps import KernelConfig
    from trusts.context import Context
    from trusts.trustee import Trustee
    from trusts.path import AuthorizationPath, AuthorizationBranch, compose
    from trusts.backends import ObjectAuthorizationBackend
    from trusts.decorators import require_authorized
    from django_trusts import TQ, condition_refs

    trusts_file = Path(trusts.__file__).resolve()
    if checkout == trusts_file or checkout in trusts_file.parents:
        raise SystemExit('Imported trusts from the checkout: %s' % trusts_file)
    if 'site-packages' not in str(trusts_file) and 'dist-packages' not in str(trusts_file):
        raise SystemExit('trusts.__file__ is not a site-packages install: %s' % trusts_file)

    leaked_tests = find_shipped_modules(ABSENT_TEST_MODULES)
    if leaked_tests:
        raise SystemExit('Test modules must not ship in the wheel: %s' % leaked_tests)

    leaked_zero = find_shipped_modules(ABSENT_ZERO_MODULES)
    if leaked_zero:
        raise SystemExit('Kernel wheel must not ship Zero modules: %s' % leaked_zero)

    if hasattr(trusts, 'ENTITY_MODEL_NAME') or hasattr(trusts, 'ROOT_PK'):
        raise SystemExit('Kernel trusts.__init__ must not export Zero constants')

    if KernelConfig.name != 'trusts' or KernelConfig.label != 'trusts_kernel':
        raise SystemExit('KernelConfig name/label mismatch: %s %s' % (
            KernelConfig.name, KernelConfig.label,
        ))

    print('wheel import ok')
    print('django', django.get_version())
    print('trusts.__file__', trusts_file)
    print('KernelConfig', KernelConfig)
    print('Context', Context)
    print('Trustee', Trustee)
    print('AuthorizationPath', AuthorizationPath)
    print('AuthorizationBranch', AuthorizationBranch)
    print('compose', compose)
    print('ObjectAuthorizationBackend', ObjectAuthorizationBackend)
    print('require_authorized', require_authorized)
    print('TQ', TQ)
    print('condition_refs', condition_refs)
    print('absent test modules', ' '.join(ABSENT_TEST_MODULES))
    print('absent zero modules', ' '.join(ABSENT_ZERO_MODULES))
    return 0


if __name__ == '__main__':
    sys.exit(main())
