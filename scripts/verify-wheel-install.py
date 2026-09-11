#!/usr/bin/env python3
"""Import-smoke the installed django-trusts wheel from outside the checkout.

C2 kernel wheel: no Zero, no concrete Trust, label ``trusts_core``.
This must not be run with the repository root as cwd or on sys.path.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


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
            'trusts',
        ],
        AUTHENTICATION_BACKENDS=['trusts.backends.TrustModelBackend'],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    )

    import django
    django.setup()

    import sys as _sys
    import trusts
    from trusts.apps import AppConfig, kernel_config
    from trusts.backends import TrustModelBackend
    from trusts.core import (
        ConditionLookup,
        Ref,
        RegisteredRelation,
        RelationPlan,
        TrustsRegistry,
        filter_authorized_scopes,
    )
    from trusts.query import AuthorizedManager, AuthorizedQuerySet
    from django_trusts import TQ, condition_refs

    trusts_file = Path(trusts.__file__).resolve()
    if checkout == trusts_file or checkout in trusts_file.parents:
        raise SystemExit('Imported trusts from the checkout: %s' % trusts_file)
    if 'site-packages' not in str(trusts_file) and 'dist-packages' not in str(trusts_file):
        raise SystemExit('trusts.__file__ is not a site-packages install: %s' % trusts_file)
    core_file = Path(trusts.core.__file__).resolve()
    if 'site-packages' not in str(core_file) and 'dist-packages' not in str(core_file):
        raise SystemExit('trusts.core is not a site-packages install: %s' % core_file)

    from django.apps import apps as django_apps

    config = kernel_config()
    if type(config) is not AppConfig:
        raise SystemExit('kernel_config() is not trusts.apps.AppConfig: %r' % (config,))
    if config.label != 'trusts_core' or config.name != 'trusts':
        raise SystemExit('C2 kernel name/label must be trusts/trusts_core: %r/%r' % (
            config.name, config.label,
        ))
    if list(config.get_models()):
        raise SystemExit('C2 kernel must expose no concrete models: %r' % (
            list(config.get_models()),
        ))
    try:
        django_apps.get_app_config('trusts')
    except LookupError:
        pass
    else:
        raise SystemExit('C2 kernel-only populate must not own label trusts')
    if 'trusts.zero' in _sys.modules:
        raise SystemExit('wheel populate imported trusts.zero')

    import trusts.models as models_mod
    try:
        from trusts.models import Trust
    except ImportError as exc:
        if 'django-trusts-zero' not in str(exc):
            raise SystemExit('shim ImportError missing documented text: %s' % exc)
    else:
        raise SystemExit('legacy Trust import succeeded without Zero: %r' % Trust)

    print('wheel import ok')
    print('django', django.get_version())
    print('trusts.__file__', trusts_file)
    print('TrustModelBackend', TrustModelBackend)
    print('kernel_config', config, config.label)
    print('AuthorizedQuerySet', AuthorizedQuerySet, AuthorizedManager)
    print('filter_authorized_scopes', filter_authorized_scopes)
    print('ConditionLookup', ConditionLookup)
    print('trusts.core', TrustsRegistry, Ref, RegisteredRelation, RelationPlan)
    print('TQ', TQ)
    print('condition_refs', condition_refs)
    print('models_shim', models_mod)
    return 0


if __name__ == '__main__':
    sys.exit(main())
