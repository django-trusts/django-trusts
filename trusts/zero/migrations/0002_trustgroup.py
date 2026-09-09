# Forward conversion of Trust.groups to an explicit TrustGroup through model.
# Existing association rows are reused (same table); local permission tuples
# start empty. Do not edit 0001_initial.

from django.db import migrations, models
from trusts.zero import GROUP_MODEL_NAME, PERMISSION_MODEL_NAME


class Migration(migrations.Migration):

    dependencies = [
        ('trusts', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[
                migrations.CreateModel(
                    name='TrustGroup',
                    fields=[
                        ('id', models.AutoField(
                            auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                        )),
                        ('group', models.ForeignKey(
                            on_delete=models.CASCADE,
                            related_name='trustgroups',
                            to=GROUP_MODEL_NAME,
                        )),
                        ('trust', models.ForeignKey(
                            on_delete=models.CASCADE,
                            related_name='trustgroups',
                            to='trusts.trust',
                        )),
                    ],
                    options={
                        'db_table': 'trusts_trust_groups',
                        'unique_together': {('trust', 'group')},
                    },
                ),
                migrations.AlterField(
                    model_name='trust',
                    name='groups',
                    field=models.ManyToManyField(
                        help_text=(
                            "Groups associated with this trust. Association "
                            "alone grants nothing; a permission applies only "
                            "when it is in both the group's global ceiling "
                            "and this trust's local TrustGroup grants."
                        ),
                        related_name='trusts',
                        through='trusts.TrustGroup',
                        to=GROUP_MODEL_NAME,
                        verbose_name='groups',
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='TrustGroupPermission',
            fields=[
                ('id', models.AutoField(
                    auto_created=True, primary_key=True, serialize=False, verbose_name='ID'
                )),
                ('permission', models.ForeignKey(
                    on_delete=models.CASCADE,
                    related_name='trustgrouppermissions',
                    to=PERMISSION_MODEL_NAME,
                )),
                ('trustgroup', models.ForeignKey(
                    on_delete=models.CASCADE,
                    related_name='trustgrouppermissions',
                    to='trusts.trustgroup',
                )),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='trustgrouppermission',
            unique_together={('trustgroup', 'permission')},
        ),
        migrations.AddField(
            model_name='trustgroup',
            name='permissions',
            field=models.ManyToManyField(
                blank=True,
                related_name='granted_trustgroups',
                through='trusts.TrustGroupPermission',
                to=PERMISSION_MODEL_NAME,
                verbose_name='permissions',
            ),
        ),
    ]
