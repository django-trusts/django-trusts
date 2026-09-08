# Align Role / RolePermission with TRUSTS_GROUP_MODEL and
# TRUSTS_PERMISSION_MODEL. 0001_initial historically hardcoded auth.Group
# and auth.Permission for Role only (Trust / TrustUserPermission already
# used the settings). Do not edit 0001_initial Role fields: already-applied
# default-model databases keep their auth FKs; this forward migration is a
# no-op when the settings still name auth.Group / auth.Permission.

from django.db import migrations, models
from trusts import GROUP_MODEL_NAME, PERMISSION_MODEL_NAME


class Migration(migrations.Migration):

    dependencies = [
        ('trusts', '0002_trustgroup'),
        migrations.swappable_dependency(GROUP_MODEL_NAME),
        migrations.swappable_dependency(PERMISSION_MODEL_NAME),
    ]

    operations = [
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
