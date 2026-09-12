#!/usr/bin/env python3
"""Import-smoke the installed django-trusts wheel from outside the checkout.

Library wheel: no Zero, no concrete Trust, no implementation AppConfig,
no Django app label, and no ``kernel_config()``. This must not be run
with the repository root as cwd or on sys.path.
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
        ],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    )

    import django
    django.setup()

    import importlib
    import sys as _sys
    import trusts
    from trusts.apps import (
        TrustsImplementationConfig,
        configured_implementation_handles,
        implementation_configs,
        implementation_for_class,
        implementation_for_path,
    )
    from trusts.backends import TrustModelBackendMixin
    from trusts.core import (
        ConditionLookup,
        Ref,
        RegisteredRelation,
        RelationPlan,
        TrustsRegistry,
        filter_authorized_scopes,
    )
    from trusts.query import AuthorizedManager, AuthorizedQuerySet
    from trusts.conditions import (
        PermissionConditionError,
        permission_condition_code,
        permission_has_condition,
    )

    trusts_file = Path(trusts.__file__).resolve()
    if checkout == trusts_file or checkout in trusts_file.parents:
        raise SystemExit('Imported trusts from the checkout: %s' % trusts_file)
    if 'site-packages' not in str(trusts_file) and 'dist-packages' not in str(trusts_file):
        raise SystemExit('trusts.__file__ is not a site-packages install: %s' % trusts_file)
    core_file = Path(trusts.core.__file__).resolve()
    if 'site-packages' not in str(core_file) and 'dist-packages' not in str(core_file):
        raise SystemExit('trusts.core is not a site-packages install: %s' % core_file)

    from django.apps import apps as django_apps

    labels = {config.label for config in django_apps.get_app_configs()}
    names = {config.name for config in django_apps.get_app_configs()}
    if 'trusts' in labels or 'trusts_core' in labels:
        raise SystemExit('library-only populate must not install a trusts app label: %r' % labels)
    if 'trusts' in names:
        raise SystemExit('library-only populate must not install an app named trusts: %r' % names)
    try:
        django_apps.get_app_config('trusts')
    except LookupError:
        pass
    else:
        raise SystemExit('library-only populate must not own label trusts')
    try:
        django_apps.get_app_config('trusts_core')
    except LookupError:
        pass
    else:
        raise SystemExit('library-only populate must not own label trusts_core')
    if hasattr(trusts.apps, 'kernel_config') or hasattr(trusts.apps, 'AppConfig'):
        raise SystemExit('library wheel still exposes kernel_config or AppConfig')
    if 'trusts.zero' in _sys.modules:
        raise SystemExit('wheel populate imported trusts.zero')
    installed_version = importlib.metadata.version('django-trusts')
    if installed_version != EXPECTED_VERSION:
        raise SystemExit(
            'installed django-trusts version is %r, expected %r' % (
                installed_version, EXPECTED_VERSION,
            )
        )
    backends_file = Path(trusts.backends.__file__).resolve()
    if checkout == backends_file or checkout in backends_file.parents:
        raise SystemExit(
            'Imported trusts.backends from the checkout: %s' % backends_file
        )
    if TrustModelBackendMixin.__module__ != 'trusts.backends':
        raise SystemExit(
            'TrustModelBackendMixin.__module__ is %r, expected trusts.backends'
            % TrustModelBackendMixin.__module__
        )
    try:
        importlib.import_module('trusts.core_backends')
    except ModuleNotFoundError:
        pass
    else:
        raise SystemExit('trusts.core_backends still imports from the library wheel')
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
    print('trusts.backends', backends_file)
    print('TrustModelBackendMixin', TrustModelBackendMixin)
    print('library apps', sorted(labels))
    print('kernel_config absent')
    print('TrustsImplementationConfig', TrustsImplementationConfig)
    print('implementation_configs', implementation_configs())
    print('AuthorizedQuerySet', AuthorizedQuerySet, AuthorizedManager)
    print('filter_authorized_scopes', filter_authorized_scopes)
    print('ConditionLookup', ConditionLookup)
    print('trusts.core', TrustsRegistry, Ref, RegisteredRelation, RelationPlan)
    print('permission_has_condition', permission_has_condition)
    print('permission_condition_code', permission_condition_code)
    print('PermissionConditionError', PermissionConditionError)
    try:
        from django_trusts import TQ  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('django_trusts still exports TQ')
    try:
        from django_trusts import condition_refs  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('django_trusts still exports condition_refs')
    try:
        from trusts.conditions import Expr  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('trusts.conditions still exports Expr')
    try:
        from trusts.conditions import condition_refs  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('trusts.conditions still exports condition_refs')
    for _hidden in (
        'ConditionLookup',
        'ConditionRecord',
        'ConditionRegistry',
        'ModelIdentity',
        'RegistryConditionLookup',
        'compile_expression_q',
        'evaluate_registered_expression',
        'obsolete_legacy_callback_setting_enabled',
        'validate_expression',
    ):
        try:
            getattr(__import__('trusts.conditions', fromlist=[_hidden]), _hidden)
        except AttributeError:
            pass
        else:
            raise SystemExit('trusts.conditions still exports %s' % _hidden)
        try:
            exec('from trusts.conditions import %s' % _hidden)
        except ImportError:
            pass
        else:
            raise SystemExit('trusts.conditions still imports %s' % _hidden)
    print('public construction imports fail')
    import importlib.util

    def _find_spec(name):
        try:
            return importlib.util.find_spec(name)
        except ModuleNotFoundError:
            return None

    if _find_spec('trusts.tests') is not None:
        raise SystemExit('installed wheel still exposes trusts.tests')
    for name in (
        'trusts.test_issue16',
        'trusts.test_issue57',
        'trusts.test_issue100',
        'trusts.test_issue115',
    ):
        if _find_spec(name) is not None:
            raise SystemExit('installed wheel still exposes %s' % name)
    if _find_spec('trusts.zero') is not None:
        raise SystemExit('installed wheel exposes trusts.zero')
    for name in (
        'trusts.authorization',
        'trusts.views',
        'trusts.urls',
        'trusts.admin',
    ):
        if _find_spec(name) is not None:
            raise SystemExit('installed wheel still exposes %s' % name)
    if hasattr(trusts, 'get_entity_model') or hasattr(trusts, 'get_permission_model'):
        raise SystemExit('library wheel still exposes Zero model getters')
    if _find_spec('trusts.zero.tests') is not None:
        raise SystemExit('installed wheel exposes trusts.zero.tests')
    for name in (
        'trusts.management',
        'trusts.management.commands',
        'trusts.management.commands.create_trust_root',
        'trusts.management.commands.grandfather_trust_group_permissions',
        'trusts.management.commands.update_roles_permissions',
    ):
        if _find_spec(name) is not None:
            raise SystemExit('installed wheel still exposes %s' % name)

    print('models_inert', models_mod)
    print('find_spec trusts.tests', _find_spec('trusts.tests'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
