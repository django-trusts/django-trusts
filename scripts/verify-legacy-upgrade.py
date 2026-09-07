#!/usr/bin/env python3
"""Upgrade a representative pre-modernization Trusts SQLite database.

Builds a 0.10.3-shaped database:

1. Apply Django contrib migrations only (auth/contenttypes/sessions/admin).
2. Create Trusts tables from the historical 0001 SQLite DDL.
3. Record ``trusts.0001_initial`` as already applied (as a 0.10.3 install
   would have).
4. Seed a root trust plus two organizations with allow/deny grants.
5. Run modern ``migrate`` without faking or reapplying Trusts 0001.
6. Smoke-check the root row and organization isolation.

This is not a captured production dump and does not replay a full Django
1.8→6.1 contrib upgrade. It is the Trusts-specific already-applied-0001
path required by #15.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / 'scripts' / 'legacy' / 'trusts_0001_sqlite.sql'


def _configure(db_path: Path) -> None:
    from django.conf import settings

    settings.configure(
        SECRET_KEY='legacy-upgrade-smoke',
        USE_TZ=True,
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.admin',
            'trusts',
        ],
        AUTHENTICATION_BACKENDS=['trusts.backends.TrustModelBackend'],
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
    return [(migration.app_label, migration.name, backwards) for migration, backwards in plan
            if migration.app_label == 'trusts']


def main() -> int:
    if not SQL_PATH.is_file():
        raise SystemExit('Missing historical DDL: %s' % SQL_PATH)

    with tempfile.TemporaryDirectory(prefix='django-trusts-legacy-upgrade-') as tmp:
        db_path = Path(tmp) / 'legacy.sqlite3'
        _configure(db_path)

        import django
        from django.core.management import call_command
        from django.db import connection

        django.setup()

        # 1. Contrib schema only. Do not apply trusts.0001_initial.
        call_command('migrate', 'contenttypes', verbosity=0, interactive=False)
        call_command('migrate', 'auth', verbosity=0, interactive=False)
        call_command('migrate', 'sessions', verbosity=0, interactive=False)
        call_command('migrate', 'admin', verbosity=0, interactive=False)

        if _applied_trusts(connection):
            raise SystemExit('Trusts migrations were applied before the legacy seed.')

        # 2–3. Historical tables + already-applied 0001 record.
        connection.close()
        raw = sqlite3.connect(db_path)
        try:
            raw.executescript(SQL_PATH.read_text())
            raw.execute(
                'INSERT INTO django_migrations (app, name, applied) VALUES (?, ?, ?)',
                ('trusts', '0001_initial', datetime.now(timezone.utc).isoformat()),
            )
            raw.execute(
                'INSERT INTO trusts_trust (id, title, settlor_id, trust_id) VALUES (1, ?, NULL, 1)',
                ('In Trust We Trust',),
            )
            raw.commit()
        finally:
            raw.close()

        if _applied_trusts(connection) != {'0001_initial'}:
            raise SystemExit('Expected only trusts.0001_initial to be recorded after the seed.')

        pending_before = _trusts_plan(connection)
        if pending_before:
            raise SystemExit('Modern tree wants extra Trusts migrations before upgrade: %s' % pending_before)

        # 4. Seed organizations after Django can see the historical tables.
        from django.contrib.auth.models import Permission, User
        from django.contrib.contenttypes.models import ContentType
        from trusts.models import Trust, TrustUserPermission

        user_a = User.objects.create_user('org_a_user', 'a@example.com', 'pass')
        user_b = User.objects.create_user('org_b_user', 'b@example.com', 'pass')
        root = Trust.objects.get(pk=1)
        org_a = Trust(settlor=user_a, title='Org A', trust=root)
        org_a.save()
        org_b = Trust(settlor=user_b, title='Org B', trust=root)
        org_b.save()
        child_a = Trust(settlor=user_a, title='Child A', trust=org_a)
        child_a.save()
        child_b = Trust(settlor=user_b, title='Child B', trust=org_b)
        child_b.save()
        denied = Trust(settlor=user_a, title='No Grant', trust=root)
        denied.save()
        denied_child = Trust(settlor=user_a, title='No Grant Child', trust=denied)
        denied_child.save()

        # 5. Modern migrate: must not reapply or fake Trusts 0001.
        call_command('migrate', verbosity=1, interactive=False)
        if _applied_trusts(connection) != {'0001_initial'}:
            raise SystemExit('Trusts migration set changed during upgrade: %s' % _applied_trusts(connection))
        pending_after = _trusts_plan(connection)
        if pending_after:
            raise SystemExit('Trusts migrations still pending after upgrade: %s' % pending_after)

        # post_migrate creates Trust content types / default permissions.
        change = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Trust),
            codename='change_trust',
        )
        TrustUserPermission(trust=org_a, entity=user_a, permission=change).save()
        TrustUserPermission(trust=org_b, entity=user_b, permission=change).save()

        user_a = User.objects.get(pk=user_a.pk)
        user_b = User.objects.get(pk=user_b.pk)
        child_a = Trust.objects.get(pk=child_a.pk)
        child_b = Trust.objects.get(pk=child_b.pk)
        denied_child = Trust.objects.get(pk=denied_child.pk)
        root = Trust.objects.get(pk=1)

        if root.trust_id != root.pk:
            raise SystemExit('Root trust is not self-referential.')
        if Trust.objects.filter(trust_id=1, id=1).count() != 1:
            raise SystemExit('Expected a single root row.')

        if not user_a.has_perm('trusts.change_trust', child_a):
            raise SystemExit('Org A user was denied on Org A content.')
        if user_a.has_perm('trusts.change_trust', child_b):
            raise SystemExit('Org A user was allowed on Org B content.')
        if not user_b.has_perm('trusts.change_trust', child_b):
            raise SystemExit('Org B user was denied on Org B content.')
        if user_b.has_perm('trusts.change_trust', child_a):
            raise SystemExit('Org B user was allowed on Org A content.')
        if user_a.has_perm('trusts.change_trust', denied_child):
            raise SystemExit('User with no grant was allowed on isolated content.')
        if user_b.has_perm('trusts.change_trust', denied_child):
            raise SystemExit('Unrelated user was allowed on isolated content.')

        print('legacy upgrade ok')
        print('django', django.get_version())
        print('db', db_path)
        print('applied trusts migrations', sorted(_applied_trusts(connection)))
        print('root', root.pk, root.title)
        print('isolation allow/deny passed')
    return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    sys.exit(main())
