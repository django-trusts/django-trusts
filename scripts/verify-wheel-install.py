#!/usr/bin/env python3
"""Import-smoke the installed django-trusts wheel from outside the checkout.

Library wheel: no Zero, no concrete Trust, no implementation AppConfig,
no Django app label, and no ``kernel_config()``. This must not be run
with the repository root as cwd or on sys.path.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import importlib.util
import sys
from pathlib import Path

EXPECTED_VERSION = '1.0.0rc1'


def _callable_shape(part, get_args):
    args = get_args(part)
    if len(args) != 2:
        raise SystemExit('condition Callable hint is %r' % (part,))
    params, ret = args
    return (tuple(params), ret)


def assert_register_signature(register) -> None:
    """Fail closed unless installed ``register`` is the 1.1 public contract.

    Ordinary roles stay one-argument path callables. Delegated registration
    adds ``delegate`` and ``sponsor`` and a second ``condition`` callable.
    ``Recorder.register`` returns ``None``.
    """
    import inspect
    from collections.abc import Callable as AbcCallable
    from typing import TypeVar, get_args, get_origin, get_type_hints

    signature = inspect.signature(register)
    param_names = [name for name in signature.parameters if name != 'self']
    expected_params = [
        'trust', 'user', 'permission', 'content', 'group',
        'delegate', 'sponsor', 'condition', 'along',
    ]
    if param_names != expected_params:
        raise SystemExit(
            'register parameters are %r, expected %r' % (param_names, expected_params)
        )
    for name in expected_params:
        if signature.parameters[name].kind != inspect.Parameter.KEYWORD_ONLY:
            raise SystemExit('register parameter %s is not keyword-only' % name)
    hints = get_type_hints(register)
    trust_hint = hints.get('trust')
    if get_origin(trust_hint) is not type:
        raise SystemExit('register trust annotation is not type[T]: %r' % trust_hint)
    trust_args = get_args(trust_hint)
    if len(trust_args) != 1 or not isinstance(trust_args[0], TypeVar):
        raise SystemExit('register trust is not type[TypeVar]: %r' % trust_hint)
    for role in ('user', 'permission', 'content', 'group'):
        role_hint = hints.get(role)
        parts = get_args(role_hint)
        if str not in parts:
            raise SystemExit('%s hint missing str: %r' % (role, role_hint))
        callable_parts = [
            part for part in parts if get_origin(part) is AbcCallable
        ]
        if len(callable_parts) != 1:
            raise SystemExit('%s hint missing Callable: %r' % (role, role_hint))
        callable_args = get_args(callable_parts[0])
        if callable_args != ([trust_args[0]], object):
            raise SystemExit(
                '%s Callable args are %r, expected [TypeVar] + object'
                % (role, callable_args)
            )
    for role in ('delegate', 'sponsor'):
        role_hint = hints.get(role)
        parts = get_args(role_hint)
        if str not in parts:
            raise SystemExit('%s hint missing str: %r' % (role, role_hint))
        if type(None) not in parts:
            raise SystemExit('%s hint missing None: %r' % (role, role_hint))
        callable_parts = [
            part for part in parts if get_origin(part) is AbcCallable
        ]
        if len(callable_parts) != 1:
            raise SystemExit('%s hint missing Callable: %r' % (role, role_hint))
        callable_args = get_args(callable_parts[0])
        if callable_args != ([trust_args[0]], object):
            raise SystemExit(
                '%s Callable args are %r, expected [TypeVar] + object'
                % (role, callable_args)
            )
    condition_hint = hints.get('condition')
    condition_parts = get_args(condition_hint)
    if type(None) not in condition_parts:
        raise SystemExit('condition hint missing None: %r' % condition_hint)
    condition_callables = [
        part for part in condition_parts if get_origin(part) is AbcCallable
    ]
    if len(condition_callables) != 2:
        raise SystemExit(
            'condition hint must include the ordinary one-argument form '
            'and the delegated two-argument form, got %r' % (condition_hint,)
        )
    shapes = [_callable_shape(part, get_args) for part in condition_callables]
    ordinary_condition = ((trust_args[0],), object)
    delegated_condition = ((trust_args[0], object), object)
    if ordinary_condition not in shapes:
        raise SystemExit(
            'ordinary condition Callable args are %r, expected [TypeVar] + object'
            % (shapes,)
        )
    if delegated_condition not in shapes:
        raise SystemExit(
            'delegated condition Callable args are %r, expected '
            '[TypeVar, object] + object' % (shapes,)
        )


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

    import sys as _sys
    import trusts
    import trusts.apps as apps_mod
    from trusts.apps import Recorder, TrustsConfigMixin
    from trusts.backends import TrustModelBackendMixin
    from trusts.decorators import filter_by_permitted_content
    from trusts.errors import PermissionConditionError
    from trusts.models import AuthorizedManager, AuthorizedManagerMixin, AuthorizedQuerySet
    from trusts.utils import parse_perm_code

    trusts_file = Path(trusts.__file__).resolve()
    if checkout == trusts_file or checkout in trusts_file.parents:
        raise SystemExit('Imported trusts from the checkout: %s' % trusts_file)
    if 'site-packages' not in str(trusts_file) and 'dist-packages' not in str(trusts_file):
        raise SystemExit('trusts.__file__ is not a site-packages install: %s' % trusts_file)
    apps_file = Path(apps_mod.__file__).resolve()
    if 'site-packages' not in str(apps_file) and 'dist-packages' not in str(apps_file):
        raise SystemExit('trusts.apps is not a site-packages install: %s' % apps_file)
    typed_marker = Path(trusts.__file__).resolve().parent / 'py.typed'
    if not typed_marker.is_file():
        raise SystemExit('installed wheel missing trusts/py.typed')
    assert_register_signature(Recorder.register)
    print('py.typed present')
    print('register contextual typing', Recorder.register)

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
    for config in django_apps.get_app_configs():
        if isinstance(config, TrustsConfigMixin):
            raise SystemExit(
                'library-only populate must not install a TrustsConfigMixin'
            )
    try:
        from trusts.backends import TrustModelBackend  # noqa: F401
    except ImportError:
        pass
    else:
        raise SystemExit('historical TrustModelBackend still imports')
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
    print('TrustsConfigMixin', TrustsConfigMixin)
    print('AuthorizedQuerySet', AuthorizedQuerySet, AuthorizedManagerMixin, AuthorizedManager)
    print('filter_by_permitted_content', filter_by_permitted_content)
    parsed = parse_perm_code('app.change_trust:own')
    if parsed[3] != 'own':
        raise SystemExit('parse_perm_code suffix is %r' % (parsed[3],))
    print('parse_perm_code', parse_perm_code)
    print('PermissionConditionError', PermissionConditionError)
    import trusts.decorators as decorators_mod
    from trusts.decorators import authorization_required
    if authorization_required is None:
        raise SystemExit('library wheel lost authorization_required')
    for _legacy in (
        'P', 'R', 'K', 'G', 'O', 'permission_required', 'request_passes_test',
    ):
        if hasattr(decorators_mod, _legacy):
            raise SystemExit(
                'library wheel still exposes trusts.decorators.%s' % _legacy
            )
        try:
            exec('from trusts.decorators import %s' % _legacy)
        except ImportError:
            pass
        else:
            raise SystemExit(
                'library wheel still imports trusts.decorators.%s' % _legacy
            )
    decorators_src = Path(decorators_mod.__file__).read_text()
    if 'trusts.zero' in decorators_src:
        raise SystemExit('library wheel decorators import Zero')
    print('legacy decorator family absent')

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
        'trusts.ordered_fold',
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
