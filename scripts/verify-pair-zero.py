#!/usr/bin/env python3
"""Matrix B: core 1.0.0.dev3 + exact Zero IIa.

Requires ZERO_CHECKOUT (django-trusts-zero at
``94e0fa109a8a7a5f53a028438ada899cbc1be1ad``) and an installed pair.
Django is configured here so the kernel tests.settings host is not used.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.pop('DJANGO_SETTINGS_MODULE', None)


def _put_kernel_first():
    kernel = Path(os.environ.get('KERNEL_CHECKOUT', ROOT)).resolve()
    zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero')).resolve()
    cleaned = []
    for p in sys.path:
        if '__editable__.django_trusts' in str(p):
            continue
        abs_p = Path(p or os.getcwd()).resolve()
        if abs_p in {ROOT.resolve(), kernel, zero}:
            continue
        if (abs_p / 'trusts' / '__init__.py').is_file() and abs_p != kernel:
            continue
        cleaned.append(p)
    sys.path[:] = cleaned
    sys.path.insert(0, str(kernel))
    if zero.is_dir():
        sys.path.append(str(zero))


_put_kernel_first()


def configure(db_path: Path) -> None:
    from django.conf import settings

    if settings.configured:
        raise SystemExit('Django already configured')
    settings.configure(
        SECRET_KEY='dev3-pair-iia',
        USE_TZ=True,
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        SILENCED_SYSTEM_CHECKS=['fields.W342'],
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.admin',
            'trusts.zero.apps.ZeroConfig',
        ],
        AUTHENTICATION_BACKENDS=[
            'django.contrib.auth.backends.ModelBackend',
            'trusts.zero.backends.TrustModelBackend',
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': str(db_path),
            }
        },
    )


def _applied_trusts(connection) -> set[str]:
    from django.db.migrations.recorder import MigrationRecorder

    recorder = MigrationRecorder(connection)
    return {name for app, name in recorder.applied_migrations() if app == 'trusts'}


def _trusts_plan(connection):
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    return [
        (migration.app_label, migration.name, backwards)
        for migration, backwards in plan
        if migration.app_label == 'trusts'
    ]


def main() -> int:
    zero = Path(os.environ.get('ZERO_CHECKOUT', ROOT / '.deps' / 'django-trusts-zero'))
    if not (zero / 'trusts' / 'zero' / 'apps.py').is_file():
        raise SystemExit('ZERO_CHECKOUT missing trusts.zero at %s' % zero)

    with tempfile.TemporaryDirectory(prefix='django-trusts-dev3-pair-') as tmp:
        db_path = Path(tmp) / 'pair.sqlite3'
        configure(db_path)

        import django
        from django.apps import apps as django_apps
        from django.core.exceptions import ImproperlyConfigured
        from django.core.management import call_command
        from django.core.management.base import CommandError
        from django.db import connection
        from django.db.migrations.loader import MigrationLoader

        django.setup()
        call_command('migrate', verbosity=0, interactive=False)

        from trusts.apps import kernel_config
        from trusts.backends import TrustModelBackendMixin
        from trusts.zero.apps import ZeroConfig
        from trusts.zero.backends import TrustModelBackend as ZeroBackend
        from trusts.zero.models import Trust as ZeroTrust

        if TrustModelBackendMixin.__module__ != 'trusts.backends':
            raise SystemExit(
                'TrustModelBackendMixin.__module__ is %r'
                % TrustModelBackendMixin.__module__
            )
        try:
            import trusts.core_backends  # noqa: F401
        except ModuleNotFoundError:
            pass
        else:
            raise SystemExit('trusts.core_backends still imports on the IIa pair')

        labels = {config.label for config in django_apps.get_app_configs()}
        if 'trusts' not in labels:
            raise SystemExit('expected Zero label trusts, got %r' % labels)
        if 'trusts_core' in labels:
            raise SystemExit('IIa pair must not install library label trusts_core')

        zero_config = django_apps.get_app_config('trusts')
        if zero_config.name != 'trusts.zero' or type(zero_config) is not ZeroConfig:
            raise SystemExit('get_app_config("trusts") is not ZeroConfig: %r' % (zero_config,))

        try:
            kernel_config()
        except ImproperlyConfigured as exc:
            if '2.0.0.dev0' not in str(exc):
                raise SystemExit('tombstone missing raw Zero version: %s' % exc)
        else:
            raise SystemExit('kernel_config() succeeded in the IIa pair')

        trusts = [m for m in django_apps.get_models() if m.__name__ == 'Trust']
        if len(trusts) != 1:
            raise SystemExit('expected exactly one Trust, got %r' % trusts)
        if trusts[0] is not ZeroTrust or ZeroTrust._meta.app_label != 'trusts':
            raise SystemExit('Trust is not Zero class under label trusts')
        if django_apps.get_model('trusts', 'Trust') is not ZeroTrust:
            raise SystemExit('get_model("trusts", "Trust") is not Zero Trust')

        import trusts.models as models_mod
        if hasattr(models_mod, 'Trust') or 'Trust' in dir(models_mod):
            raise SystemExit('inert trusts.models still exposes Trust')
        try:
            from trusts.models import Trust as ShimTrust
        except (ImportError, AttributeError):
            pass
        else:
            raise SystemExit('trusts.models.Trust must not forward: %r' % ShimTrust)

        try:
            from trusts.backends import TrustModelBackend
        except ImportError:
            pass
        else:
            raise SystemExit('core historical TrustModelBackend still imports: %r' % (
                TrustModelBackend,
            ))
        from trusts.zero.backends import TrustModelBackend as ImportedZero
        if ImportedZero is not ZeroBackend:
            raise SystemExit('canonical Zero backend mismatch')

        loader = MigrationLoader(connection)
        keys = {key for key in loader.disk_migrations if key[0] == 'trusts'}
        expected = {('trusts', '0001_initial'), ('trusts', '0002_trustgroup')}
        if keys != expected:
            raise SystemExit('loader keys %s' % keys)
        initial = loader.disk_migrations[('trusts', '0001_initial')]
        group = loader.disk_migrations[('trusts', '0002_trustgroup')]
        if initial.__module__ != 'trusts.zero.migrations.0001_initial':
            raise SystemExit('0001 module %s' % initial.__module__)
        if group.__module__ != 'trusts.zero.migrations.0002_trustgroup':
            raise SystemExit('0002 module %s' % group.__module__)
        for migration, label in ((initial, '0001'), (group, '0002')):
            origin = Path(sys.modules[migration.__module__].__file__).resolve()
            if 'trusts/zero/migrations' not in str(origin).replace('\\', '/'):
                raise SystemExit('%s origin not under Zero: %s' % (label, origin))

        applied = _applied_trusts(connection)
        if applied != {'0001_initial', '0002_trustgroup'}:
            raise SystemExit('applied set %s' % applied)
        if _trusts_plan(connection):
            raise SystemExit('already-current plan not empty: %s' % (
                _trusts_plan(connection),
            ))

        try:
            call_command('makemigrations', 'trusts', check=True, verbosity=0)
        except CommandError as exc:
            raise SystemExit('makemigrations --check failed: %s' % exc)

        print('pair-zero ok')
        print('django', django.get_version())
        print('zero', zero_config.name, zero_config.label)
        print('Trust', ZeroTrust, ZeroTrust._meta.app_label)
        print('loader', sorted(keys))
        print('applied', sorted(applied))
        print('makemigrations --check quiet')
        print('already-current migrate --plan empty')
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    raise SystemExit(main())
