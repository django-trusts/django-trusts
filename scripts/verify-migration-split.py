#!/usr/bin/env python3
"""Prove historical Trusts migration identity after the Zero relocation.

Covers:

1. Fresh install applies ``{0001_initial, 0002_trustgroup}`` and creates
   the root row.
2. ``sqlmigrate`` matches the pre-split DDL snapshot for both names.
3. Already-applied 0001+0002: ``migrate --plan`` for app_label ``trusts``
   is empty; row counts and content-type natural keys are unchanged.
4. ``makemigrations trusts --check`` is quiet (no ``0003``).
5. Loader disk keys remain ``('trusts', '0001_initial')`` /
   ``('trusts', '0002_trustgroup')``.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_0001 = ROOT / 'scripts' / 'expected' / 'trusts_0001_initial.sql'
EXPECTED_0002 = ROOT / 'scripts' / 'expected' / 'trusts_0002_trustgroup.sql'

TRUSTS_TABLES = (
    'trusts_trust',
    'trusts_trustuserpermission',
    'trusts_trust_groups',
    'trusts_trustgrouppermission',
    'trusts_role',
    'trusts_rolepermission',
)

CONTENT_TYPE_KEYS = (
    ('trusts', 'trust'),
    ('trusts', 'trustuserpermission'),
    ('trusts', 'role'),
    ('trusts', 'rolepermission'),
    ('trusts', 'trustgroup'),
    ('trusts', 'trustgrouppermission'),
)


def _configure(db_path: Path) -> None:
    from django.conf import settings

    settings.configure(
        SECRET_KEY='migration-split-smoke',
        USE_TZ=True,
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.admin',
            'trusts.apps.KernelConfig',
            'trusts.zero.apps.ZeroConfig',
        ],
        AUTHENTICATION_BACKENDS=['trusts.zero.backends.TrustModelBackend'],
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


def _table_counts(db_path: Path) -> dict[str, int]:
    conn = sqlite3.connect(db_path)
    try:
        counts = {}
        for table in TRUSTS_TABLES:
            counts[table] = conn.execute(
                'SELECT COUNT(*) FROM %s' % table
            ).fetchone()[0]
        return counts
    finally:
        conn.close()


def _content_type_keys():
    from django.contrib.contenttypes.models import ContentType

    return {
        (ct.app_label, ct.model)
        for ct in ContentType.objects.filter(app_label='trusts')
    }


def _sqlmigrate(name: str) -> str:
    from django.core.management import call_command

    out = StringIO()
    call_command('sqlmigrate', 'trusts', name, stdout=out)
    return out.getvalue()


def _assert_sql_matches(name: str, expected_path: Path) -> None:
    actual = _sqlmigrate(name)
    expected = expected_path.read_text()
    if actual != expected:
        raise SystemExit(
            'sqlmigrate trusts %s diverged from pre-split snapshot %s' % (
                name, expected_path,
            )
        )


def main() -> int:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', '')
    if not EXPECTED_0001.is_file() or not EXPECTED_0002.is_file():
        raise SystemExit('Missing pre-split sqlmigrate snapshots in scripts/expected/')

    with tempfile.TemporaryDirectory(prefix='django-trusts-migration-split-') as tmp:
        db_path = Path(tmp) / 'fresh.sqlite3'
        _configure(db_path)

        import django
        django.setup()

        from django.apps import apps
        from django.core.management import call_command
        from django.db import connection
        from django.db.migrations.loader import MigrationLoader
        from trusts.apps import KernelConfig
        from trusts.zero.apps import ZeroConfig
        from trusts.zero.models import Trust

        kernel = apps.get_app_config('trusts_kernel')
        zero = apps.get_app_config('trusts')
        if kernel.name != KernelConfig.name or kernel.label != 'trusts_kernel':
            raise SystemExit('Kernel AppConfig mismatch: %s %s' % (kernel.name, kernel.label))
        if zero.name != ZeroConfig.name or zero.label != 'trusts':
            raise SystemExit('Zero AppConfig mismatch: %s %s' % (zero.name, zero.label))
        if kernel.models_module is not None:
            raise SystemExit('Kernel app must own no models')
        migrations_module = getattr(zero, 'module', None)
        loader = MigrationLoader(connection, ignore_no_migrations=True)
        if ('trusts', '0001_initial') not in loader.disk_migrations:
            raise SystemExit('disk_migrations missing (trusts, 0001_initial)')
        if ('trusts', '0002_trustgroup') not in loader.disk_migrations:
            raise SystemExit('disk_migrations missing (trusts, 0002_trustgroup)')
        disk_0001 = loader.disk_migrations[('trusts', '0001_initial')]
        if disk_0001.__module__ != 'trusts.zero.migrations.0001_initial':
            raise SystemExit('0001 module path is %s' % disk_0001.__module__)

        call_command('migrate', verbosity=0)
        applied = _applied_trusts(connection)
        if applied != {'0001_initial', '0002_trustgroup'}:
            raise SystemExit('fresh install applied set %s' % applied)
        plan = _trusts_plan(connection)
        if plan:
            raise SystemExit('fresh install trusts plan not empty: %s' % plan)
        if not Trust.objects.filter(pk=Trust._meta.get_field('trust').default).exists():
            # ROOT_PK default is 1
            from trusts.zero import ROOT_PK
            if not Trust.objects.filter(pk=ROOT_PK).exists():
                raise SystemExit('fresh install missing root trust')

        _assert_sql_matches('0001_initial', EXPECTED_0001)
        _assert_sql_matches('0002_trustgroup', EXPECTED_0002)

        keys = _content_type_keys()
        missing = [pair for pair in CONTENT_TYPE_KEYS if pair not in keys]
        if missing:
            raise SystemExit('missing content-type natural keys: %s' % missing)

        counts = _table_counts(db_path)
        call_command('migrate', verbosity=0)
        if _trusts_plan(connection):
            raise SystemExit('already-current migrate --plan not empty')
        if _applied_trusts(connection) != {'0001_initial', '0002_trustgroup'}:
            raise SystemExit('already-current applied set changed')
        if _table_counts(db_path) != counts:
            raise SystemExit('already-current row counts changed: %s -> %s' % (
                counts, _table_counts(db_path),
            ))
        if _content_type_keys() != keys:
            raise SystemExit('already-current content-type keys changed')

        out = StringIO()
        err = StringIO()
        try:
            call_command(
                'makemigrations', 'trusts', check_changes=True, dry_run=True,
                verbosity=0, stdout=out, stderr=err,
            )
        except Exception as exc:
            raise SystemExit(
                'makemigrations trusts --check failed: %s\n%s%s' % (
                    exc, out.getvalue(), err.getvalue(),
                )
            )
        combined = out.getvalue() + err.getvalue()
        if '0003' in combined or 'AlterModelBases' in combined:
            raise SystemExit('makemigrations proposed extra operations:\n%s' % combined)

        print('migration split ok')
        print('kernel', kernel.name, kernel.label)
        print('zero', zero.name, zero.label)
        print('applied', sorted(applied))
        print('disk', '0001_initial', disk_0001.__module__)
        print('root_pk', Trust.objects.get(pk=1).pk)
        print('tables', ' '.join(TRUSTS_TABLES))
        print('content_types', ' '.join('%s.%s' % pair for pair in CONTENT_TYPE_KEYS))
        print('row_counts', counts)
        return 0


if __name__ == '__main__':
    sys.exit(main())
