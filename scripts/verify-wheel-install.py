#!/usr/bin/env python3
"""Import-smoke the installed django-trusts wheel from outside the checkout.

Step III library wheel: no Zero, no concrete Trust, no implementation
AppConfig, failure-only ``kernel_config()`` tombstone. This must not be
run with the repository root as cwd or on sys.path.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
from pathlib import Path

EXPECTED_VERSION = '1.0.0.dev3'


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
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    )

    import django
    django.setup()

    import sys as _sys
    import trusts
    import trusts.core_backends as core_backends
    from django.core.exceptions import ImproperlyConfigured
    from trusts.apps import (
        KERNEL_CONFIG_TOMBSTONE,
        AppConfig,
        TrustsImplementationConfig,
        configured_implementation_handles,
        implementation_configs,
        implementation_for_class,
        implementation_for_path,
        kernel_config,
    )
    from trusts.backends import TrustModelBackendMixin
    from trusts.core_backends import (
        TrustModelBackendMixin as CoreTrustModelBackendMixin,
    )
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

    config = django_apps.get_app_config('trusts_core')
    if type(config) is not AppConfig:
        raise SystemExit('library AppConfig is not trusts.apps.AppConfig: %r' % (config,))
    if config.label != 'trusts_core' or config.name != 'trusts':
        raise SystemExit('library name/label must be trusts/trusts_core: %r/%r' % (
            config.name, config.label,
        ))
    if list(config.get_models()):
        raise SystemExit('library must expose no concrete models: %r' % (
            list(config.get_models()),
        ))
    try:
        django_apps.get_app_config('trusts')
    except LookupError:
        pass
    else:
        raise SystemExit('library-only populate must not own label trusts')
    if 'trusts.zero' in _sys.modules:
        raise SystemExit('wheel populate imported trusts.zero')
    try:
        kernel_config()
    except ImproperlyConfigured as exc:
        if str(exc) != KERNEL_CONFIG_TOMBSTONE:
            raise SystemExit('tombstone text mismatch: %s' % exc)
        if '2.0.0.dev0' not in str(exc):
            raise SystemExit('tombstone missing raw Zero version: %s' % exc)
    else:
        raise SystemExit('kernel_config() succeeded; tombstone required')
    installed_version = importlib.metadata.version('django-trusts')
    if installed_version != EXPECTED_VERSION:
        raise SystemExit(
            'installed django-trusts version is %r, expected %r' % (
                installed_version, EXPECTED_VERSION,
            )
        )
    core_backends_file = Path(core_backends.__file__).resolve()
    if checkout == core_backends_file or checkout in core_backends_file.parents:
        raise SystemExit(
            'Imported trusts.core_backends from the checkout: %s' % (
                core_backends_file,
            )
        )
    if (
        'site-packages' not in str(core_backends_file)
        and 'dist-packages' not in str(core_backends_file)
    ):
        raise SystemExit(
            'trusts.core_backends is not a site-packages install: %s' % (
                core_backends_file,
            )
        )
    if TrustModelBackendMixin is not CoreTrustModelBackendMixin:
        raise SystemExit(
            'trusts.backends.TrustModelBackendMixin is not '
            'trusts.core_backends.TrustModelBackendMixin'
        )
    if issubclass(AppConfig, TrustsImplementationConfig):
        raise SystemExit('library AppConfig must not be a TrustsImplementationConfig')
    if implementation_configs() != ():
        raise SystemExit('library-only wheel must expose no implementation configs')
    if configured_implementation_handles() != ():
        raise SystemExit('library-only wheel must expose no implementation handles')
    try:
        from trusts.backends import TrustModelBackend  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('historical TrustModelBackend still imports')
    try:
        implementation_for_path('trusts.backends.TrustModelBackend')
    except Exception as exc:
        if 'No implementation owns' not in str(exc):
            raise SystemExit('unexpected implementation_for_path error: %s' % exc)
    else:
        raise SystemExit('implementation_for_path succeeded without an owner')
    if implementation_for_class(type(TrustModelBackendMixin()), required=False) is not None:
        raise SystemExit('library-only wheel must not own the mixin class')

    import trusts.models as models_mod
    try:
        from trusts.models import Trust
    except (ImportError, AttributeError):
        pass
    else:
        raise SystemExit('legacy Trust import succeeded without Zero: %r' % Trust)
    if hasattr(models_mod, 'Trust') or 'Trust' in dir(models_mod):
        raise SystemExit('inert trusts.models still exposes Trust')

    print('wheel import ok')
    print('django', django.get_version())
    print('django-trusts', installed_version)
    print('trusts.__file__', trusts_file)
    print('trusts.core_backends', core_backends_file)
    print('TrustModelBackendMixin', TrustModelBackendMixin)
    print('core_backends mixin identity', TrustModelBackendMixin is CoreTrustModelBackendMixin)
    print('library AppConfig', config, config.label)
    print('kernel_config tombstone ok')
    print('TrustsImplementationConfig', TrustsImplementationConfig)
    print('implementation_configs', implementation_configs())
    print('AuthorizedQuerySet', AuthorizedQuerySet, AuthorizedManager)
    print('filter_authorized_scopes', filter_authorized_scopes)
    print('ConditionLookup', ConditionLookup)
    print('trusts.core', TrustsRegistry, Ref, RegisteredRelation, RelationPlan)
    print('TQ', TQ)
    print('condition_refs', condition_refs)
    print('models_inert', models_mod)
    return 0


if __name__ == '__main__':
    sys.exit(main())
