# Align Role / RolePermission with TRUSTS_GROUP_MODEL and
# TRUSTS_PERMISSION_MODEL. 0001_initial historically hardcoded auth.Group
# and auth.Permission for Role only (Trust / TrustUserPermission already
# used the settings). Do not edit 0001_initial Role fields: already-applied
# default-model databases keep their auth FKs; this forward migration is a
# no-op when the settings still name auth.Group / auth.Permission.
#
# When the settings name other models, existing Role join rows still store
# auth.Group / auth.Permission primary keys. Retargeting those FKs without
# a data step would reinterpret IDs across model classes. The RunPython
# below deletes the affected joins first (fail closed). Rebuild with
# update_roles_permissions and explicit Role.groups assignments.

from django.db import migrations, models
from trusts import GROUP_MODEL_NAME, PERMISSION_MODEL_NAME


def clear_role_joins_before_retarget(apps, schema_editor):
    group_retarget = GROUP_MODEL_NAME != 'auth.Group'
    perm_retarget = PERMISSION_MODEL_NAME != 'auth.Permission'
    if not group_retarget and not perm_retarget:
        return
    connection = schema_editor.connection
    qn = connection.ops.quote_name
    with connection.cursor() as cursor:
        if group_retarget:
            cursor.execute('DELETE FROM %s' % qn('trusts_role_groups'))
        if perm_retarget:
            cursor.execute('DELETE FROM %s' % qn('trusts_rolepermission'))


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('trusts', '0002_trustgroup'),
        migrations.swappable_dependency(GROUP_MODEL_NAME),
        migrations.swappable_dependency(PERMISSION_MODEL_NAME),
    ]

    operations = [
        migrations.RunPython(clear_role_joins_before_retarget, noop_reverse),
        migrations.AlterField(
            model_name='rolepermission',
            name='permission',
            field=models.ForeignKey(
                on_delete=models.CASCADE,
                related_name='rolepermissions',
                to=PERMISSION_MODEL_NAME,
            ),
        ),
        migrations.AlterField(
            model_name='role',
            name='groups',
            field=models.ManyToManyField(
                related_name='roles',
                to=GROUP_MODEL_NAME,
                verbose_name='groups',
            ),
        ),
        migrations.AlterField(
            model_name='role',
            name='permissions',
            field=models.ManyToManyField(
                related_name='roles',
                through='trusts.RolePermission',
                to=PERMISSION_MODEL_NAME,
                verbose_name='permissions',
            ),
        ),
    ]
