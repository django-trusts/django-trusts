from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import trusts.zero.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('trusts_tests', '0001_test_models'),
    ]

    operations = [
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('manager', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='managed_organizations', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Ticket',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('status', models.CharField(default='open', max_length=20)),
                ('region', models.CharField(blank=True, max_length=40, null=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tickets', to='trusts_tests.organization')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tickets', to=settings.AUTH_USER_MODEL)),
                ('trust', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='trusts_tests_ticket_content', to='trusts.trust')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
            },
            bases=(trusts.zero.models.ReadonlyFieldsMixin, models.Model),
        ),
    ]
