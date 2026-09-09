from django.db import migrations, models
import django.db.models.deletion
import trusts.zero.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
        ('trusts', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('trust', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='trusts_tests_category_content', to='trusts.trust')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
                'permissions': (('add_topic_to_category', 'Add topic to a category'),),
            },
            bases=(trusts.zero.models.ReadonlyFieldsMixin, models.Model),
        ),
        migrations.CreateModel(
            name='TestGroupJunction',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('content', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='auth.group', unique=True)),
                ('trust', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='trusts_tests_testgroupjunction', to='trusts.trust')),
            ],
            options={
                'default_permissions': (),
            },
            bases=(trusts.zero.models.ReadonlyFieldsMixin, models.Model),
        ),
        migrations.AlterUniqueTogether(
            name='testgroupjunction',
            unique_together={('content',)},
        ),
    ]
