#!/usr/bin/env python3
"""Fail-closed Role retarget when TRUSTS_*_MODEL is not auth.*.

Applies custom-model migrations through ``0002_trustgroup``, seeds Role
joins against ``auth.Group`` / ``auth.Permission`` that collide with
custom-model primary keys, then applies ``0003_role_configured_models``.

0003 must delete those joins before AlterField. Reinterpreting auth pk=7
as CustomGroup pk=7 (or auth.Permission pk as CustomPermission pk) is a
silent authorization change and is not allowed.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix='django-trusts-role-upgrade-') as tmp:
        db_path = Path(tmp) / 'custom.sqlite3'
        os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.custom_settings'
        import tests.custom_settings as custom_settings
        custom_settings.DATABASES['default'] = {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': str(db_path),
        }

        import django
        from django.core.management import call_command
        from django.db import connection

        django.setup()

        call_command('migrate', 'contenttypes', verbosity=0, interactive=False)
        call_command('migrate', 'auth', verbosity=0, interactive=False)
        call_command('migrate', 'custom_auth', verbosity=0, interactive=False)
        call_command('migrate', 'trusts', '0002_trustgroup', verbosity=0, interactive=False)

        from django.contrib.auth.models import Group as AuthGroup
        from django.contrib.auth.models import Permission as AuthPermission
        from tests.custom_auth.models import CustomGroup, CustomPermission
        from trusts.models import Role, RolePermission
        from trusts.utils import sync_configured_permissions

        sync_configured_permissions()

        collide_pk = 7
        auth_group = AuthGroup(pk=collide_pk, name='auth-seven')
        auth_group.save()
        custom_group = CustomGroup(pk=collide_pk, name='custom-seven')
        custom_group.save()

        auth_perm = AuthPermission.objects.order_by('pk').first()
        if auth_perm is None:
            raise SystemExit('Expected auth.Permission rows after contrib migrate.')
        try:
            custom_perm = CustomPermission.objects.get(pk=auth_perm.pk)
        except CustomPermission.DoesNotExist:
            custom_perm = CustomPermission(
                pk=auth_perm.pk,
                name='colliding-custom',
                content_type=auth_perm.content_type,
                codename='collide_%s' % auth_perm.pk,
            )
            custom_perm.save()
        if custom_perm.pk != auth_perm.pk:
            raise SystemExit(
                'Could not place CustomPermission at auth.Permission pk=%s.'
                % auth_perm.pk
            )

        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO trusts_role (id, name) VALUES (1, %s)',
                ['colliding-role'],
            )
            cursor.execute(
                'INSERT INTO trusts_role_groups (role_id, group_id) VALUES (1, %s)',
                [collide_pk],
            )
            cursor.execute(
                'INSERT INTO trusts_rolepermission '
                '(managed, permission_id, role_id) VALUES (1, %s, 1)',
                [auth_perm.pk],
            )

        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT COUNT(*) FROM %s' % connection.ops.quote_name(
                    'trusts_role_groups'
                )
            )
            if cursor.fetchone()[0] != 1:
                raise SystemExit('Failed to seed colliding Role.groups join.')
            cursor.execute(
                'SELECT COUNT(*) FROM %s' % connection.ops.quote_name(
                    'trusts_rolepermission'
                )
            )
            if cursor.fetchone()[0] != 1:
                raise SystemExit('Failed to seed colliding RolePermission row.')

        call_command('migrate', verbosity=1, interactive=False)

        role = Role.objects.get(name='colliding-role')
        if role.groups.filter(pk=collide_pk).exists():
            raise SystemExit(
                '0003 reinterpreted auth.Group pk=%s as CustomGroup pk=%s.'
                % (collide_pk, collide_pk)
            )
        if RolePermission.objects.filter(role=role).exists():
            raise SystemExit(
                '0003 kept RolePermission rows that would retarget auth.Permission '
                'ids onto CustomPermission.'
            )
        if not CustomGroup.objects.filter(pk=collide_pk, name='custom-seven').exists():
            raise SystemExit('Custom group pk=%s was deleted unexpectedly.' % collide_pk)
        if not AuthGroup.objects.filter(pk=collide_pk, name='auth-seven').exists():
            raise SystemExit('auth.Group pk=%s was deleted unexpectedly.' % collide_pk)
        if not CustomPermission.objects.filter(pk=auth_perm.pk).exists():
            raise SystemExit(
                'CustomPermission pk=%s was deleted unexpectedly.' % auth_perm.pk
            )

        print('custom role upgrade ok')
        print('django', django.get_version())
        print('cleared colliding Role.groups / RolePermission before retarget')
        return 0


if __name__ == '__main__':
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    sys.exit(main())
