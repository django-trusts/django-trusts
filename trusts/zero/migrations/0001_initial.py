from django.db import migrations, models
from django.conf import settings

from trusts.zero import (
    ENTITY_MODEL_NAME, GROUP_MODEL_NAME, PERMISSION_MODEL_NAME,
    DEFAULT_SETTLOR, ALLOW_NULL_SETTLOR, ROOT_PK,
)
from trusts.zero.management.commands.create_trust_root import create_root_trust
from trusts.zero.models import ReadonlyFieldsMixin


def forward(apps, schema_editor):
    if getattr(settings, 'TRUSTS_CREATE_ROOT', True):
        Trust = apps.get_model('trusts', 'trust')
        pk = getattr(settings, 'TRUSTS_ROOT_PK', 1)
        settlor = getattr(settings, 'TRUSTS_ROOT_SETTLOR', None)
        title = getattr(settings, 'TRUSTS_ROOT_TITLE', 'In Trust We Trust')
        create_root_trust(Trust, pk, settlor, title)

def backward(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0006_require_contenttypes_0002'),
    ]

    operations = [
        migrations.CreateModel(
            name='Trust',
            fields=[
                ('id', models.AutoField(verbose_name='ID', auto_created=True, primary_key=True, serialize=False)),
                ('title', models.CharField(verbose_name='title', max_length=40)),
                ('settlor', models.ForeignKey(to=ENTITY_MODEL_NAME, default=DEFAULT_SETTLOR, null=ALLOW_NULL_SETTLOR, on_delete=models.CASCADE)),
                ('trust', models.ForeignKey(to='trusts.Trust', related_name='%(app_label)s_%(class)s_content', default=ROOT_PK, on_delete=models.CASCADE)),
                ('groups', models.ManyToManyField(to=GROUP_MODEL_NAME, related_name='trusts', verbose_name='groups', help_text='The groups this trust grants permissions to. A user willget all permissions granted to each of his/her group.')),
            ],
            options={
                'default_permissions': ('add', 'change', 'delete', 'read'),
            },
            bases=(ReadonlyFieldsMixin, models.Model),
        ),
        migrations.CreateModel(
            name='TrustUserPermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, verbose_name='ID', serialize=False)),
                ('entity', models.ForeignKey(to=ENTITY_MODEL_NAME, related_name='trustpermissions', on_delete=models.CASCADE)),
                ('permission', models.ForeignKey(to=PERMISSION_MODEL_NAME, related_name='trustentities', on_delete=models.CASCADE)),
                ('trust', models.ForeignKey(to='trusts.Trust', related_name='trustees', on_delete=models.CASCADE)),
            ],
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('managed', models.BooleanField(default=False)),
                ('permission', models.ForeignKey(to='auth.Permission', related_name='rolepermissions', on_delete=models.CASCADE)),
            ],
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=80, unique=True, help_text="The name of the role. Corresponds to the key of model's trusts option.")),
                ('groups', models.ManyToManyField(related_name='roles', verbose_name='groups', to='auth.Group')),
                ('permissions', models.ManyToManyField(to='auth.Permission', related_name='roles', through='trusts.RolePermission', verbose_name='permissions')),
            ],
        ),
        migrations.AddField(
            model_name='rolepermission',
            name='role',
            field=models.ForeignKey(to='trusts.Role', related_name='rolepermissions', on_delete=models.CASCADE),
        ),
        migrations.AlterUniqueTogether(
            name='trust',
            unique_together=set([('settlor', 'title')]),
        ),
        migrations.AlterUniqueTogether(
            name='rolepermission',
            unique_together=set([('role', 'permission')]),
        ),
        migrations.AlterUniqueTogether(
            name='trustuserpermission',
            unique_together=set([('trust', 'entity', 'permission')]),
        ),
        migrations.RunPython(forward, backward)
    ]
